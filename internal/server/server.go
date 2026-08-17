// Package server wires the router and middleware chain.
package server

import (
	"errors"
	"fmt"
	"io"
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
	r.Method(http.MethodGet, "/v1/limits", handlers.Limits(d.MaxBlobBytes, d.MaxBlobBytes+AuthEnvelopeSlack))

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

// AuthEnvelopeSlack is the headroom allowed above the blob cap for the BRC-104 envelope
// the auth middleware wraps around the payload.
const AuthEnvelopeSlack int64 = 64 * 1024

// maxBody caps request bodies and answers oversize requests itself.
//
// It must answer BEFORE the auth middleware, and that ordering is the whole point. The
// middleware reads the entire body to build the signature payload, so with a plain
// MaxBytesReader the read failed inside auth and the caller was told "invalid
// authentication" — sending them off to debug BRC-31 headers for what was only ever a
// size problem. Here the guard owns the failure: it counts bytes, and if the body runs
// past the cap it writes 413 with a size-shaped message no matter what the wrapped
// handler tried to say.
//
// Counting rather than trusting Content-Length is deliberate: the header is
// client-declared and absent entirely on a chunked upload.
func maxBody(blobLimit int64) func(http.Handler) http.Handler {
	bodyLimit := blobLimit + AuthEnvelopeSlack
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > bodyLimit {
				writeTooLarge(w, blobLimit)
				return
			}
			g := &sizeGuard{ResponseWriter: w, blobLimit: blobLimit}
			r.Body = &countingBody{rc: r.Body, limit: bodyLimit, guard: g}
			next.ServeHTTP(g, r)
			// Nothing downstream wrote a response — a handler that abandoned the request
			// on the read error still owes the caller an answer.
			if g.over && !g.wrote {
				g.WriteHeader(http.StatusRequestEntityTooLarge)
			}
		})
	}
}

func writeTooLarge(w http.ResponseWriter, blobLimit int64) {
	responses.WriteError(w, http.StatusRequestEntityTooLarge, "ERR_BLOB_TOO_LARGE",
		fmt.Sprintf("Blob exceeds the maximum permitted size of %d bytes. GET /v1/limits reports the current cap.", blobLimit))
}

// errBodyTooLarge stops the read that overran the cap. It never reaches the caller; the
// guard converts it into the 413.
var errBodyTooLarge = errors.New("request body exceeds the permitted size")

// countingBody fails the read once the body overruns, and tells the guard why.
type countingBody struct {
	rc    io.ReadCloser
	limit int64
	read  int64
	guard *sizeGuard
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	b.read += int64(n)
	if b.read > b.limit {
		b.guard.over = true
		return n, errBodyTooLarge
	}
	return n, err
}

func (b *countingBody) Close() error { return b.rc.Close() }

// sizeGuard replaces whatever the wrapped handler says with a 413 once the body overran.
//
// The auth middleware reports a failed body read as an authentication failure. That answer
// is wrong and it is expensive to debug, so it is discarded here rather than corrected
// upstream in a dependency.
type sizeGuard struct {
	http.ResponseWriter
	blobLimit int64
	over      bool
	wrote     bool
}

func (g *sizeGuard) WriteHeader(code int) {
	if g.wrote {
		return
	}
	g.wrote = true
	if g.over {
		// Drop any x-bsv-auth-* headers the middleware staged for its own error.
		clear(g.ResponseWriter.Header())
		writeTooLarge(g.ResponseWriter, g.blobLimit)
		return
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *sizeGuard) Write(b []byte) (int, error) {
	if !g.wrote {
		g.WriteHeader(http.StatusOK)
	}
	if g.over {
		// Body already written by writeTooLarge; swallow the handler's version.
		return len(b), nil
	}
	return g.ResponseWriter.Write(b)
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
