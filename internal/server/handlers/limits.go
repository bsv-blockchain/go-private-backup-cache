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
func Limits(maxBlobBytes, maxBodyBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		responses.WriteJSON(w, http.StatusOK, map[string]any{
			"status":       "success",
			"maxBlobBytes": maxBlobBytes,
			"maxBodyBytes": maxBodyBytes,
		})
	})
}
