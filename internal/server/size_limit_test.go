package server_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/nonce"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/handlers"
	walletpkg "github.com/bsv-blockchain/go-private-backup-cache/internal/wallet"
)

// An oversized upload used to surface as an authentication failure: the old auth layer
// read the body to build its signature payload, hit the body cap first, and reported
// "invalid authentication". Callers went hunting through auth headers for what was only
// ever a size problem. The size guard must answer before auth does.

func testRouter(t *testing.T, maxBlobBytes int64) http.Handler {
	t.Helper()
	key, err := ec.NewPrivateKey()
	require.NoError(t, err)
	w, err := walletpkg.NewServerIdentity(hex.EncodeToString(key.Serialize()))
	require.NoError(t, err)
	r, err := server.NewRouter(server.Deps{
		Wallet:       w,
		Store:        blobstore.NewMemoryStore(),
		Nonces:       nonce.NewMemoryStore(),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxBlobBytes: maxBlobBytes,
	})
	require.NoError(t, err)
	return r
}

func TestOversizeUploadReports413NotAuthFailure(t *testing.T) {
	const maxBlobBytes = 4096
	r := testRouter(t, maxBlobBytes)

	// One byte past the blob cap — which is the body cap exactly, the proof rides in a
	// header — and sent with no proof at all: the size answer must still win over the
	// auth answer.
	body := bytes.Repeat([]byte("x"), int(maxBlobBytes+1))
	req := httptest.NewRequest(http.MethodPost, "/v1/log/"+secDevice+"?seq=1&generation=1", bytes.NewReader(body))
	req.Header.Set("Content-Type", handlers.ContentTypeOctetStream)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	require.NotContains(t, strings.ToLower(rec.Body.String()), "authentication")
	require.Contains(t, rec.Body.String(), "ERR_BLOB_TOO_LARGE")
}

// Under the cap the guard must be invisible: this request carries no X-Bsv-Auth header, so
// it has to reach the auth middleware and be refused there, not swallowed by the guard.
func TestUnderCapUploadStillReachesAuth(t *testing.T) {
	const maxBlobBytes = 4096
	r := testRouter(t, maxBlobBytes)

	req := httptest.NewRequest(http.MethodPost, "/v1/log/"+secDevice+"?seq=1&generation=1",
		bytes.NewReader(bytes.Repeat([]byte("x"), 1024)))
	req.Header.Set("Content-Type", handlers.ContentTypeOctetStream)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_AUTH_REQUIRED")
}

// The client hardcoded its own copy of the cap and silently drifted out of sync with the
// server's. Publishing the number unauthenticated lets it read the real one instead — and
// the server's identity key rides along because no proof can be built without it.
func TestLimitsEndpointIsPublicAndReportsTheCap(t *testing.T) {
	const maxBlobBytes = 7 << 20
	r := testRouter(t, maxBlobBytes)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/limits", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	var got struct {
		Status            string `json:"status"`
		MaxBlobBytes      int64  `json:"maxBlobBytes"`
		MaxBodyBytes      int64  `json:"maxBodyBytes"`
		ServerIdentityKey string `json:"serverIdentityKey"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, "success", got.Status)
	require.Equal(t, int64(maxBlobBytes), got.MaxBlobBytes)
	// No envelope slack any more: the body on the wire IS the blob, byte for byte.
	require.Equal(t, got.MaxBlobBytes, got.MaxBodyBytes)
	// Clients derive their proof's signing key toward this key as counterparty, so it must
	// be a usable compressed public key, not a placeholder.
	require.Regexp(t, `^0[23][0-9a-f]{64}$`, got.ServerIdentityKey)
}
