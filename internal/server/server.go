// Package server wires the router and middleware chain.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	sdkwallet "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/nonce"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/handlers"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/middlewares"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/responses"
)

// Deps are the server's collaborators.
type Deps struct {
	Wallet       sdkwallet.Interface
	Store        blobstore.BlobStore
	Nonces       nonce.Store
	Logger       *slog.Logger
	MaxBlobBytes int64
	Port         int
}

// NewRouter builds the HTTP handler.
//
// Authentication is a per-request @bsv/auth proof carried in one header and verified
// before the body is read — see internal/authproof. There is no handshake, no session
// state and no signed response envelope, which is what allows request and response bodies
// to stream and replicas to scale without sticky sessions.
func NewRouter(d Deps) (http.Handler, error) {
	pub, err := d.Wallet.GetPublicKey(context.Background(), sdkwallet.GetPublicKeyArgs{IdentityKey: true}, "")
	if err != nil {
		return nil, fmt.Errorf("read server identity key: %w", err)
	}
	serverIdentityKey := pub.PublicKey.ToDERHex()

	r := chi.NewRouter()
	r.Use(chimw.RequestID, chimw.Recoverer)
	r.Use(corsMiddleware)
	r.Use(maxBody(d.MaxBlobBytes))

	r.Method(http.MethodGet, "/health", handlers.Health(d.Store))
	// Unauthenticated, deliberately: the cap and the server's identity key are what a
	// client needs BEFORE it can build its first proof.
	r.Method(http.MethodGet, "/v1/limits", handlers.Limits(d.MaxBlobBytes, serverIdentityKey))

	// NOTE: no payment middleware, deliberately and permanently. See README — charging
	// would require the client's real wallet to fund a transaction, whose BEEF carries
	// complete prior transactions of that wallet, binding the pseudonym to the user's coin
	// graph. It would also force this service to hold a funded wallet and a per-user
	// payment ledger.
	r.Group(func(r chi.Router) {
		r.Use(middlewares.AuthProof(d.Wallet, d.Nonces, d.Logger))

		r.Get("/v1/manifest", handlers.Manifest(d.Store))
		r.Post("/v1/log/{deviceId}", handlers.Append(d.Store))
		r.Get("/v1/log/{deviceId}", handlers.Index(d.Store))
		r.Get("/v1/log/{deviceId}/{seq}", handlers.Blob(d.Store))
		r.Delete("/v1/generation/{deviceId}/{generation}", handlers.PruneGeneration(d.Store))
		// Erasure on request. Separate from pruning because it must ignore the retention
		// guard that pruning exists to enforce — see handlers.DeleteAccount.
		r.Delete("/v1/account", handlers.DeleteAccount(d.Store))
	})

	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		responses.WriteError(w, http.StatusNotFound, "ERR_NOT_FOUND", "No such route.")
	})

	return r, nil
}

// StreamTimeout bounds one whole request — body upload and response download included.
//
// Generous on purpose: 200 MiB at a slow-but-honest 1 Mbit/s takes ~28 minutes. What it
// exists to stop is the unbounded case: an upload's store transaction pins a pooled
// database connection for as long as the body keeps trickling, the nonce store shares
// that pool, and every authentication needs the nonce store — so without a ceiling, ~25
// deliberately slow streams would stall auth for everyone. With it, the worst such an
// attacker buys is this window.
const StreamTimeout = 30 * time.Minute

// New builds the http.Server.
func New(d Deps) (*http.Server, error) {
	h, err := NewRouter(d)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              fmt.Sprintf(":%d", d.Port),
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       StreamTimeout,
		WriteTimeout:      StreamTimeout,
		IdleTimeout:       2 * time.Minute,
	}, nil
}

// maxBody caps request bodies and answers oversize requests itself.
//
// It must answer BEFORE the auth layer touches the request, so that an oversize upload is
// reported as a size problem rather than an authentication failure. The cap needs no
// envelope slack any more: the proof travels in a header, so the body on the wire IS the
// blob, byte for byte.
//
// Counting rather than trusting Content-Length is deliberate: the header is
// client-declared and absent entirely on a chunked upload.
func maxBody(blobLimit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > blobLimit {
				writeTooLarge(w, blobLimit)
				return
			}
			g := &sizeGuard{ResponseWriter: w, blobLimit: blobLimit}
			r.Body = &countingBody{rc: r.Body, limit: blobLimit, guard: g}
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
// A handler that saw its read fail mid-stream reports an internal error; that answer is
// wrong for what was only ever a size problem, so it is discarded here.
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
		// Drop whatever the handler staged for its own answer — but keep the CORS
		// headers the outer middleware set, or a browser client is forbidden from
		// reading the very 413 that tells it what went wrong.
		h := g.Header()
		for name := range h {
			if !strings.HasPrefix(name, "Access-Control-") {
				delete(h, name)
			}
		}
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
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
