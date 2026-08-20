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
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/handlers"
	walletpkg "github.com/bsv-blockchain/go-private-backup-cache/internal/wallet"
)

// An oversized upload used to surface as an authentication failure: the auth middleware
// reads the body to build the signature payload, hit the body cap first, and reported
// "invalid authentication". Callers went hunting through BRC-31 headers for what was only
// ever a size problem. The size guard must answer before auth does.

func testRouter(t *testing.T, maxBlobBytes int64) http.Handler {
	t.Helper()
	key, err := ec.NewPrivateKey()
	require.NoError(t, err)
	w, err := walletpkg.NewServerIdentity(hex.EncodeToString(key.Serialize()))
	require.NoError(t, err)
	return server.NewRouter(server.Deps{
		Wallet:       w,
		Store:        blobstore.NewMemoryStore(),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxBlobBytes: maxBlobBytes,
	})
}

func TestOversizeUploadReports413NotAuthFailure(t *testing.T) {
	const maxBlobBytes = 4096
	r := testRouter(t, maxBlobBytes)

	// Comfortably past the blob cap plus the auth envelope slack, and sent with no
	// BRC-103 credentials at all — the size answer must still win over the auth answer.
	body := bytes.Repeat([]byte("x"), int(maxBlobBytes+server.AuthEnvelopeSlack+1))
	req := httptest.NewRequest(http.MethodPost, "/v1/log/"+secDevice+"?seq=1&generation=1", bytes.NewReader(body))
	req.Header.Set("Content-Type", handlers.ContentTypeOctetStream)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	require.NotContains(t, strings.ToLower(rec.Body.String()), "authentication")
	require.Contains(t, rec.Body.String(), "ERR_BLOB_TOO_LARGE")
}

// Under the cap the guard must be invisible: this request is still unauthenticated, so it
// has to reach the auth middleware and be refused there, not swallowed by the guard.
func TestUnderCapUploadStillReachesAuth(t *testing.T) {
	const maxBlobBytes = 4096
	r := testRouter(t, maxBlobBytes)

	req := httptest.NewRequest(http.MethodPost, "/v1/log/"+secDevice+"?seq=1&generation=1",
		bytes.NewReader(bytes.Repeat([]byte("x"), 1024)))
	req.Header.Set("Content-Type", handlers.ContentTypeOctetStream)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// The client hardcoded its own copy of the cap and silently drifted out of sync with the
// server's. Publishing the number unauthenticated lets it read the real one instead.
func TestLimitsEndpointIsPublicAndReportsTheCap(t *testing.T) {
	const maxBlobBytes = 7 << 20
	r := testRouter(t, maxBlobBytes)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/limits", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	var got struct {
		Status       string `json:"status"`
		MaxBlobBytes int64  `json:"maxBlobBytes"`
		MaxBodyBytes int64  `json:"maxBodyBytes"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, "success", got.Status)
	require.Equal(t, int64(maxBlobBytes), got.MaxBlobBytes)
	require.Equal(t, int64(maxBlobBytes)+server.AuthEnvelopeSlack, got.MaxBodyBytes)
}
