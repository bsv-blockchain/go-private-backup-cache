package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// The middleware is tested directly here because the interesting case only arises once
// something downstream actually reads the body. An unauthenticated request never gets that
// far — the auth middleware refuses it on the missing proof header before touching a byte —
// so the router-level test cannot reach this path. In production the downstream reader is
// the store streaming an authenticated upload, and it is that read whose mid-stream failure
// would otherwise be reported as something other than a size problem.

// readAllThenClaimAuthFailure stands in for the downstream reader: it consumes the body,
// then answers with whatever it makes of the read error. Here it does the wrong thing on
// purpose — blaming authentication, the historical misreport this guard exists to override.
func readAllThenClaimAuthFailure(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, `{"error":"invalid authentication"}`, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestGuardOverridesDownstreamAnswerOnOverflow(t *testing.T) {
	const blobLimit int64 = 4096
	h := maxBody(blobLimit)(readAllThenClaimAuthFailure(t))

	body := bytes.Repeat([]byte("x"), int(blobLimit+1))
	req := httptest.NewRequest(http.MethodPost, "/v1/log/dev", bytes.NewReader(body))
	// No declared length: the guard has to count rather than read the header.
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_BLOB_TOO_LARGE")
	require.NotContains(t, rec.Body.String(), "authentication")
}

// A body of exactly the cap must pass: the proof travels in a header, so the body on the
// wire IS the blob and the cap needs no envelope slack on top.
func TestGuardLeavesUnderCapRequestsAlone(t *testing.T) {
	const blobLimit int64 = 4096
	h := maxBody(blobLimit)(readAllThenClaimAuthFailure(t))

	req := httptest.NewRequest(http.MethodPost, "/v1/log/dev",
		bytes.NewReader(bytes.Repeat([]byte("x"), int(blobLimit))))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNoContent, rec.Code)
}

func TestGuardRejectsOnDeclaredLengthWithoutReading(t *testing.T) {
	const blobLimit int64 = 4096
	reached := false
	h := maxBody(blobLimit)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/v1/log/dev", bytes.NewReader([]byte("x")))
	req.ContentLength = blobLimit + 1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	require.False(t, reached, "an oversize declared length must not reach the handler at all")
}
