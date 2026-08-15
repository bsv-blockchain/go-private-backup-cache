// Package responses writes the service's uniform JSON envelope.
//
// Success bodies carry "status":"success"; errors carry a SCREAMING_SNAKE code and a human
// sentence. This matches the convention used across the other BSV Go services.
package responses

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// ErrorBody is the error envelope.
type ErrorBody struct {
	Status      string `json:"status"`
	Code        string `json:"code"`
	Description string `json:"description"`
}

// WriteJSON writes payload as JSON with the given status.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}

// WriteError writes the error envelope.
//
// Descriptions are for humans and must never include internal detail — no SQL, no stack,
// no other pseudonym's data.
func WriteError(w http.ResponseWriter, status int, code, description string) {
	WriteJSON(w, status, ErrorBody{Status: "error", Code: code, Description: description})
}
