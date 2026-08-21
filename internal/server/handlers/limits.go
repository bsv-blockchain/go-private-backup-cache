package handlers

import (
	"net/http"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/responses"
)

// Limits handles GET /v1/limits. Unauthenticated, deliberately.
//
// Clients previously carried their own copy of the blob cap as a constant and silently
// drifted out of sync with the server's — a wallet would encrypt and sign a chunk the
// server was always going to refuse. The number is not a secret and knowing it grants no
// capability, so it is published where a client can read it before doing that work.
//
// serverIdentityKey rides along because a client cannot build its first auth proof
// without it: the proof's signing key is derived toward this key as counterparty. It is
// public by definition. maxBodyBytes equals maxBlobBytes now that the proof travels in a
// header instead of an envelope around the body; the field stays so clients keep one shape.
func Limits(maxBlobBytes int64, serverIdentityKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		responses.WriteJSON(w, http.StatusOK, map[string]any{
			"status":            "success",
			"maxBlobBytes":      maxBlobBytes,
			"maxBodyBytes":      maxBlobBytes,
			"serverIdentityKey": serverIdentityKey,
		})
	})
}
