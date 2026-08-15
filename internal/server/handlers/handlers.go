// Package handlers implements the HTTP endpoints.
//
// Every handler that touches stored data derives the account address from the
// authenticated identity and nothing else. There is no identity parameter in this API.
package handlers

import (
	"net/http"
	"regexp"
	"strconv"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/middlewares"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/responses"
)

// deviceIDPattern matches a client-generated opaque device id: 16 random bytes as
// lowercase hex. Constraining the shape keeps arbitrary strings out of storage keys.
var deviceIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// pseudonym returns the authenticated caller's compressed DER hex, or "" when the request
// is unauthenticated (in which case it has already written a 401).
//
// This is the single choke point for account addressing. If a future handler needs an
// account, it calls this — it never reads one from the request.
func pseudonym(w http.ResponseWriter, r *http.Request) string {
	key := middlewares.GetIdentityKey(r.Context())
	if key == nil {
		responses.WriteError(w, http.StatusUnauthorized, "ERR_AUTH_REQUIRED", "Authentication required.")
		return ""
	}
	return key.ToDERHex()
}

// deviceID validates and returns the {deviceId} path parameter.
func deviceID(w http.ResponseWriter, raw string) (string, bool) {
	if !deviceIDPattern.MatchString(raw) {
		responses.WriteError(w, http.StatusBadRequest,
			"ERR_INVALID_DEVICE_ID", "Device id must be 32 lowercase hexadecimal characters.")
		return "", false
	}
	return raw, true
}

// positiveIntParam reads a required positive integer query parameter.
func positiveIntParam(r *http.Request, name string) (int, bool) {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || v < 1 {
		return 0, false
	}
	return v, true
}

// optionalIntParam reads an optional integer query parameter.
func optionalIntParam(r *http.Request, name string, fallback int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return fallback
	}
	return v
}
