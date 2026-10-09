package handlers

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/responses"
)

// Pinger reports backing-store reachability.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Health handles GET /health. Unauthenticated, so probes can reach it.
//
// The store error goes to the log, not the response: db.Ping failures carry hosts, ports
// and role names, and this endpoint is public. A probe only needs the bit.
func Health(p Pinger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := p.Ping(r.Context()); err != nil {
			slog.Error("health check failed", "error", err)
			responses.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status":  "degraded",
				"details": map[string]any{"store": "unreachable"},
			})
			return
		}
		responses.WriteJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"details": map[string]any{"store": "ok"},
		})
	})
}
