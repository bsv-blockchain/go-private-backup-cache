package middlewares_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkwallet "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/authproof"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/nonce"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/middlewares"
)

// The middleware is exercised without chi on purpose: its contract is with net/http alone
// (a header in, an identity in the context and a digest-checking body out), and a router
// in the harness would hide a dependency the middleware must not have.

// recordingNext captures what the protected handler actually observes, because several
// properties here are about the handler's view — the identity in the context, and whether
// reading the body to EOF succeeds — not about the response.
type recordingNext struct {
	called   bool
	identity *ec.PublicKey
	body     []byte
	bodyErr  error
}

func (n *recordingNext) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n.called = true
	n.identity = middlewares.GetIdentityKey(r.Context())
	n.body, n.bodyErr = io.ReadAll(r.Body)
	w.WriteHeader(http.StatusOK)
}

type harness struct {
	clientWallet sdkwallet.Interface
	clientKey    string
	serverKey    string
	next         *recordingNext
	handler      http.Handler
}

// newHarness builds a fresh middleware chain with its own nonce store, so replay behavior
// in one test can never bleed into another.
func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWithNonces(t, nonce.NewMemoryStore())
}

// newHarnessWithNonces exists for the tests about the nonce store itself: what the
// middleware does when single-use enforcement cannot be answered is a property of the
// middleware, not of any particular store.
func newHarnessWithNonces(t *testing.T, nonces nonce.Store) *harness {
	t.Helper()

	serverPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverWallet, err := sdkwallet.NewCompletedProtoWallet(serverPriv)
	require.NoError(t, err)

	clientPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	clientWallet, err := sdkwallet.NewCompletedProtoWallet(clientPriv)
	require.NoError(t, err)

	next := &recordingNext{}
	mw := middlewares.AuthProof(serverWallet, nonces,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	return &harness{
		clientWallet: clientWallet,
		clientKey:    clientPriv.PubKey().ToDERHex(),
		serverKey:    serverPriv.PubKey().ToDERHex(),
		next:         next,
		handler:      mw(next),
	}
}

// header signs action as the client at the given time and renders the X-Bsv-Auth value.
func (h *harness) header(t *testing.T, action string, now time.Time) string {
	t.Helper()
	p, err := authproof.Sign(context.Background(), h.clientWallet, h.serverKey, action, now)
	require.NoError(t, err)
	hv, err := authproof.Encode(p)
	require.NoError(t, err)
	return hv
}

// send drives one request through the middleware. body may be nil for bodyless requests.
func (h *harness) send(t *testing.T, method, uri, headerValue string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, uri, rdr)
	if headerValue != "" {
		req.Header.Set(authproof.Header, headerValue)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestARequestWithoutAProofHeaderIsRefused(t *testing.T) {
	h := newHarness(t)
	rec := h.send(t, http.MethodGet, "/v1/manifest", "", nil)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_AUTH_REQUIRED")
	require.False(t, h.next.called, "an unauthenticated request reached the handler")
}

func TestAGarbageProofHeaderIsRefused(t *testing.T) {
	h := newHarness(t)
	rec := h.send(t, http.MethodGet, "/v1/manifest", "not-base64!!!", nil)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_AUTH_REQUIRED")
	require.False(t, h.next.called)
}

func TestAValidGetProofPassesAndTheHandlerSeesTheCallersIdentity(t *testing.T) {
	h := newHarness(t)
	hv := h.header(t, authproof.Action(http.MethodGet, "/v1/manifest", ""), time.Now())
	rec := h.send(t, http.MethodGet, "/v1/manifest", hv, nil)

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, h.next.called)
	require.NotNil(t, h.next.identity, "middleware passed without injecting an identity")
	require.Equal(t, h.clientKey, h.next.identity.ToDERHex(),
		"handler saw a different identity than the one that signed the proof")
}

func TestAProofForADifferentURIIsRefused(t *testing.T) {
	h := newHarness(t)
	// Signed for the manifest, sent against a device log: the action binding must hold
	// even though the signature itself is genuine.
	hv := h.header(t, authproof.Action(http.MethodGet, "/v1/manifest", ""), time.Now())
	rec := h.send(t, http.MethodGet, "/v1/log/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?generation=1", hv, nil)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.False(t, h.next.called)
}

func TestAReplayedProofIsRefusedTheSecondTime(t *testing.T) {
	h := newHarness(t)
	hv := h.header(t, authproof.Action(http.MethodGet, "/v1/manifest", ""), time.Now())

	first := h.send(t, http.MethodGet, "/v1/manifest", hv, nil)
	require.Equal(t, http.StatusOK, first.Code)

	// Identical header, well inside the validity window: only the nonce store can stop it.
	second := h.send(t, http.MethodGet, "/v1/manifest", hv, nil)
	require.Equal(t, http.StatusUnauthorized, second.Code)
	require.Contains(t, second.Body.String(), "ERR_AUTH_REQUIRED")
}

func TestAnUploadProofWithoutABodyDigestIsRefused(t *testing.T) {
	h := newHarness(t)
	uri := "/v1/log/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?seq=1&generation=1"
	// A genuine signature over a digestless action: nothing would bind the body, so the
	// middleware must refuse before a single body byte is trusted.
	hv := h.header(t, authproof.Action(http.MethodPost, uri, ""), time.Now())
	rec := h.send(t, http.MethodPost, uri, hv, []byte("payload"))

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.False(t, h.next.called)
}

func TestAnUploadWhoseBodyMatchesTheSignedDigestReadsCleanlyToEOF(t *testing.T) {
	h := newHarness(t)
	body := bytes.Repeat([]byte("cipher"), 512)
	uri := "/v1/log/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?seq=1&generation=1"
	hv := h.header(t, authproof.Action(http.MethodPost, uri, sha256Hex(body)), time.Now())
	rec := h.send(t, http.MethodPost, uri, hv, body)

	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, h.next.called)
	require.NoError(t, h.next.bodyErr, "a matching body must read to EOF without error")
	require.Equal(t, body, h.next.body)
}

func TestAnUploadWhoseBodyDoesNotMatchTheSignedDigestFailsTheHandlersRead(t *testing.T) {
	h := newHarness(t)
	uri := "/v1/log/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?seq=1&generation=1"
	// The proof binds one body, the wire carries another. Auth itself passes — the sender
	// is genuine — so the mismatch must surface where a store would see it: as a read error
	// at EOF, aborting whatever transaction the bytes were streaming into.
	hv := h.header(t, authproof.Action(http.MethodPost, uri, sha256Hex([]byte("the body I signed"))), time.Now())
	h.send(t, http.MethodPost, uri, hv, []byte("a different body"))

	require.True(t, h.next.called, "an authenticated upload must reach the handler")
	require.ErrorIs(t, h.next.bodyErr, middlewares.ErrBodyDigestMismatch)
}

// brokenNonceStore models the nonce backend being unreachable: Consume can neither
// confirm nor deny reuse.
type brokenNonceStore struct{}

func (brokenNonceStore) Consume(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("nonce store unreachable")
}

func TestANonceStoreFailureIsAnInternalErrorAndTheHandlerNeverRuns(t *testing.T) {
	h := newHarnessWithNonces(t, brokenNonceStore{})
	// A perfectly valid proof: signature, freshness and action all hold, so the request
	// reaches the consume step and fails there. Waving it through would turn a store
	// outage into a replay window, so the middleware must fail closed — and as a 500,
	// because retrying with a fresh proof is exactly the right client response and a 401
	// would tell it to fix credentials that are not broken.
	hv := h.header(t, authproof.Action(http.MethodGet, "/v1/manifest", ""), time.Now())
	rec := h.send(t, http.MethodGet, "/v1/manifest", hv, nil)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_INTERNAL")
	require.False(t, h.next.called, "a request with unverifiable single-use reached the handler")
}

func TestAnExpiredProofIsRefused(t *testing.T) {
	h := newHarness(t)
	// Signed 10 minutes ago: past the 2-minute window plus skew, so freshness alone must
	// refuse it even though the signature verifies.
	hv := h.header(t, authproof.Action(http.MethodGet, "/v1/manifest", ""), time.Now().Add(-10*time.Minute))
	rec := h.send(t, http.MethodGet, "/v1/manifest", hv, nil)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_AUTH_REQUIRED")
	require.False(t, h.next.called)
}
