// Package middlewares holds this service's own HTTP middleware.
package middlewares

import (
	"context"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type ctxKey struct{}

var identityContextKey = ctxKey{}

// GetIdentityKey returns the authenticated caller's public key, or nil.
//
// This is the ONLY source of an account address in this service. No handler may take a
// pseudonym from a request body, query parameter, path segment or header — doing so is the
// cross-tenant auth bypass this design exists to avoid.
func GetIdentityKey(ctx context.Context) *ec.PublicKey {
	k, _ := ctx.Value(identityContextKey).(*ec.PublicKey)
	return k
}

// WithIdentityKey injects a verified identity. Used by AuthProof and by tests.
func WithIdentityKey(ctx context.Context, k *ec.PublicKey) context.Context {
	return context.WithValue(ctx, identityContextKey, k)
}
