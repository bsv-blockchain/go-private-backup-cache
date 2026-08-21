package middlewares

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/authproof"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/nonce"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/responses"
)

// ErrBodyDigestMismatch surfaces from the request body reader when the streamed bytes do
// not hash to the digest the proof signed. By then the sender is authenticated and the
// bytes are inside an open store transaction, which the error aborts — nothing is kept.
var ErrBodyDigestMismatch = errors.New("body does not match the digest bound into the auth proof")

var sha256HexPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// AuthProof authenticates every request from a single X-Bsv-Auth header, before the body
// is touched. That ordering is the design: it is what lets 200 MB uploads stream to
// storage instead of being buffered for a trailing signature.
//
// The proof signs "METHOD requestURI" (plus " sha256=<hex>" of the body on uploads), so a
// proof for one route cannot be replayed against another, and the nonce store refuses the
// same proof twice. For uploads the body is not trusted on the proof alone: the digest the
// proof signed is checked against the actual bytes as the handler streams them, via the
// body wrapper installed here.
func AuthProof(w wallet.Interface, nonces nonce.Store, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			headerValue := r.Header.Get(authproof.Header)
			if headerValue == "" {
				responses.WriteError(rw, http.StatusUnauthorized,
					"ERR_AUTH_REQUIRED", "Authentication required: missing "+authproof.Header+" header.")
				return
			}
			proof, err := authproof.Decode(headerValue)
			if err != nil {
				responses.WriteError(rw, http.StatusUnauthorized,
					"ERR_AUTH_REQUIRED", "Authentication required: proof is malformed.")
				return
			}

			// The expected action is rebuilt from the request line, with the digest taken
			// from the proof itself — the signature makes the digest trustworthy, and the
			// body wrapper below makes it binding.
			digest := authproof.BodySha256(proof.Action)
			if digest != "" && !sha256HexPattern.MatchString(digest) {
				responses.WriteError(rw, http.StatusUnauthorized,
					"ERR_AUTH_REQUIRED", "Authentication required: body digest is not a sha256 hex.")
				return
			}
			if r.Method == http.MethodPost && digest == "" {
				responses.WriteError(rw, http.StatusUnauthorized,
					"ERR_AUTH_REQUIRED", "Authentication required: an upload proof must bind the body digest.")
				return
			}
			expected := authproof.Action(r.Method, r.URL.RequestURI(), digest)

			identity, err := authproof.Verify(r.Context(), w, proof, expected, time.Now())
			if err != nil {
				log.Info("auth proof refused", "reason", err, "path", r.URL.Path)
				responses.WriteError(rw, http.StatusUnauthorized,
					"ERR_AUTH_REQUIRED", "Authentication required: "+refusalReason(err))
				return
			}

			// Single-use, and only after the signature held — otherwise anyone could burn
			// nonces into the store unauthenticated.
			fresh, err := nonces.Consume(r.Context(), proof.Nonce, time.UnixMilli(proof.ExpiresAt))
			if err != nil {
				log.Error("nonce store failed", "error", err)
				responses.WriteError(rw, http.StatusInternalServerError,
					"ERR_INTERNAL", "Could not check the proof for reuse.")
				return
			}
			if !fresh {
				responses.WriteError(rw, http.StatusUnauthorized,
					"ERR_AUTH_REQUIRED", "Authentication required: proof already used.")
				return
			}

			if digest != "" {
				r.Body = &digestVerifyingBody{rc: r.Body, hasher: sha256.New(), want: digest}
			}
			next.ServeHTTP(rw, r.WithContext(WithIdentityKey(r.Context(), identity)))
		})
	}
}

// refusalReason maps verification errors to client-facing text. The distinctions are not
// secrets — an attacker learns nothing a correct client would not need to fix itself.
func refusalReason(err error) string {
	switch {
	case errors.Is(err, authproof.ErrExpired):
		return "proof expired."
	case errors.Is(err, authproof.ErrTooFarFuture):
		return "proof expiry too far in the future."
	case errors.Is(err, authproof.ErrActionMismatch):
		return "proof does not describe this request."
	default:
		return "proof signature invalid."
	}
}

// digestVerifyingBody hashes the body as the handler streams it and turns EOF into
// ErrBodyDigestMismatch when the bytes do not match what the proof signed. A store
// mid-transaction sees the error as a failed read and rolls back.
type digestVerifyingBody struct {
	rc     io.ReadCloser
	hasher hash.Hash
	want   string
	failed bool
}

func (b *digestVerifyingBody) Read(p []byte) (int, error) {
	if b.failed {
		return 0, ErrBodyDigestMismatch
	}
	n, err := b.rc.Read(p)
	if n > 0 {
		b.hasher.Write(p[:n])
	}
	if errors.Is(err, io.EOF) {
		if hex.EncodeToString(b.hasher.Sum(nil)) != b.want {
			b.failed = true
			return n, ErrBodyDigestMismatch
		}
	}
	return n, err
}

func (b *digestVerifyingBody) Close() error { return b.rc.Close() }
