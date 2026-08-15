package handlers

import (
	"net/http"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/responses"
)

// Pinger reports backing-store reachability.
type Pinger interface{ Ping() error }

// Health handles GET /health. Unauthenticated, so probes can reach it.
func Health(p Pinger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := p.Ping(); err != nil {
			responses.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status":  "degraded",
				"details": map[string]any{"store": err.Error()},
			})
			return
		}
		responses.WriteJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"details": map[string]any{"store": "ok"},
		})
	})
}
