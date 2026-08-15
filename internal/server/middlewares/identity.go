// Package middlewares holds this service's own HTTP middleware.
package middlewares

import (
	"context"
	"net/http"

	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/responses"
)

type ctxKey struct{}

var identityContextKey = ctxKey{}

// RequireIdentityKey rejects any request without a verified BRC-103/104 peer identity and
// re-stashes the verified key under a local context key.
//
// The re-stash is what makes handlers unit-testable: the auth library's own context key is
// unexported, so without this a handler test could only ever assert a 401.
func RequireIdentityKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, err := middleware.ShouldGetAuthenticatedIdentity(r.Context())
		if err != nil || key == nil || middleware.IsUnknownIdentity(key) {
			responses.WriteError(w, http.StatusUnauthorized,
				"ERR_AUTH_REQUIRED", "Authentication required.")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithIdentityKey(r.Context(), key)))
	})
}

// GetIdentityKey returns the authenticated caller's public key, or nil.
//
// This is the ONLY source of an account address in this service. No handler may take a
// pseudonym from a request body, query parameter, path segment or header — doing so is the
// cross-tenant auth bypass this design exists to avoid.
func GetIdentityKey(ctx context.Context) *ec.PublicKey {
	k, _ := ctx.Value(identityContextKey).(*ec.PublicKey)
	return k
}

// WithIdentityKey injects a verified identity. Used by RequireIdentityKey and by tests.
func WithIdentityKey(ctx context.Context, k *ec.PublicKey) context.Context {
	return context.WithValue(ctx, identityContextKey, k)
}
