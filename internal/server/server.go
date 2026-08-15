// Package server wires the router and middleware chain.
package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
	"github.com/bsv-blockchain/go-sdk/auth"
	sdkwallet "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/handlers"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/middlewares"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/responses"
)

// Deps are the server's collaborators.
type Deps struct {
	Wallet       sdkwallet.Interface
	Store        blobstore.BlobStore
	Logger       *slog.Logger
	MaxBlobBytes int64
	Port         int
}

// NewRouter builds the HTTP handler.
//
// MOUNTING CONSTRAINT: the auth middleware must cover the ORIGIN ROOT. It intercepts
// POST /.well-known/auth on an exact path compare and never calls the wrapped handler,
// while the TypeScript client always posts its handshake to `${new URL(url).origin}
// /.well-known/auth`. Mounting only under a subtree such as /api means the handshake never
// reaches the middleware and every subsequent request 401s with session-not-found.
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.RequestID, chimw.Recoverer)
	r.Use(corsMiddleware)
	r.Use(maxBody(d.MaxBlobBytes))

	r.Method(http.MethodGet, "/health", handlers.Health(d.Store))

	// One SessionManager shared by both mounts below.
	//
	// It is in-process. Running more than one replica requires either sticky sessions at
	// the load balancer or a shared auth.SessionManager implementation (five methods:
	// AddSession/UpdateSession/GetSession/RemoveSession/HasSession) — none ships with the
	// library. The failure mode is silent from the client's view: a handshake on replica A
	// followed by a request on replica B returns 401 session-not-found.
	sessions := auth.NewSessionManager()

	authMW := middleware.NewAuth(d.Wallet,
		middleware.WithAuthDisallowUnauthenticated(),
		middleware.WithAuthSessionManager(sessions),
		middleware.WithAuthLogger(d.Logger),
	)

	// Handled entirely inside the middleware; the wrapped handler is never reached.
	r.Handle("/.well-known/auth", authMW.HTTPHandler(http.NotFoundHandler()))

	// NOTE: no payment middleware, deliberately and permanently. See README — charging
	// would require the client's real wallet to fund a transaction, whose BEEF carries
	// complete prior transactions of that wallet, binding the pseudonym to the user's coin
	// graph inside a request that BRC-104 has already signed. It would also force this
	// service to hold a funded wallet and a per-user payment ledger.
	r.Group(func(r chi.Router) {
		r.Use(authMW.HTTPHandler)
		r.Use(middlewares.RequireIdentityKey)

		r.Get("/v1/manifest", handlers.Manifest(d.Store))
		r.Post("/v1/log/{deviceId}", handlers.Append(d.Store, d.MaxBlobBytes))
		r.Get("/v1/log/{deviceId}", handlers.Index(d.Store))
		r.Get("/v1/log/{deviceId}/{seq}", handlers.Blob(d.Store))
		r.Delete("/v1/generation/{deviceId}/{generation}", handlers.PruneGeneration(d.Store))
	})

	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		responses.WriteError(w, http.StatusNotFound, "ERR_NOT_FOUND", "No such route.")
	})

	return r
}

// New builds the http.Server.
func New(d Deps) *http.Server {
	return &http.Server{
		Addr:              fmt.Sprintf(":%d", d.Port),
		Handler:           NewRouter(d),
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// maxBody caps request bodies before a handler allocates.
func maxBody(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Slack above the blob cap covers the auth envelope the middleware adds.
			r.Body = http.MaxBytesReader(w, r.Body, n+64*1024)
			next.ServeHTTP(w, r)
		})
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		// AuthFetch reads the x-bsv-auth-* response headers; without this they are hidden
		// from browser clients and the handshake fails in a confusing way.
		w.Header().Set("Access-Control-Expose-Headers", "*")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
