package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkwallet "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/authproof"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/nonce"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/handlers"
)

// This suite runs the whole stack — real router, real middleware chain, real HTTP over a
// listener — with clients that behave exactly as the TypeScript one does: learn the server
// key from /v1/limits, build the action from the literal request line, sign, and send.
// If a property holds here, it holds for the wire protocol, not just for a handler in
// isolation.

const (
	e2eMaxBlobBytes = int64(16 << 20)
	e2eAliceDevice  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	e2eBobDevice    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type e2eEnv struct {
	base            string
	walletKey       string // the server wallet's identity key, straight from the key pair
	publishedKey    string // what /v1/limits actually told the clients to verify against
	publishedLimits struct {
		Status            string `json:"status"`
		MaxBlobBytes      int64  `json:"maxBlobBytes"`
		MaxBodyBytes      int64  `json:"maxBodyBytes"`
		ServerIdentityKey string `json:"serverIdentityKey"`
	}
}

type e2eClient struct {
	wallet    sdkwallet.Interface
	serverKey string
	base      string
}

// newE2E boots a real server and two client identities. The clients take the server key
// from the unauthenticated /v1/limits response — the discovery path a first-contact client
// has no alternative to — so every authenticated request in the suite also proves that
// published key is the one proofs verify against.
func newE2E(t *testing.T) (*e2eEnv, *e2eClient, *e2eClient) {
	t.Helper()

	serverPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverWallet, err := sdkwallet.NewCompletedProtoWallet(serverPriv)
	require.NoError(t, err)

	h, err := server.NewRouter(server.Deps{
		Wallet:       serverWallet,
		Store:        blobstore.NewMemoryStore(),
		Nonces:       nonce.NewMemoryStore(),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxBlobBytes: e2eMaxBlobBytes,
	})
	require.NoError(t, err)

	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)

	env := &e2eEnv{base: ts.URL, walletKey: serverPriv.PubKey().ToDERHex()}

	// No auth header on purpose: this must work before the client can sign anything.
	resp, err := http.Get(ts.URL + "/v1/limits")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&env.publishedLimits))
	require.NoError(t, resp.Body.Close())
	env.publishedKey = env.publishedLimits.ServerIdentityKey

	return env, newE2EClient(t, env), newE2EClient(t, env)
}

func newE2EClient(t *testing.T, env *e2eEnv) *e2eClient {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	w, err := sdkwallet.NewCompletedProtoWallet(priv)
	require.NoError(t, err)
	return &e2eClient{wallet: w, serverKey: env.publishedKey, base: env.base}
}

// authHeader signs the action a request with this method, URI and body would carry.
func (c *e2eClient) authHeader(t *testing.T, method, uri string, body []byte) string {
	t.Helper()
	digest := ""
	if body != nil {
		sum := sha256.Sum256(body)
		digest = hex.EncodeToString(sum[:])
	}
	p, err := authproof.Sign(context.Background(), c.wallet, c.serverKey,
		authproof.Action(method, uri, digest), time.Now())
	require.NoError(t, err)
	hv, err := authproof.Encode(p)
	require.NoError(t, err)
	return hv
}

// send performs one real HTTP request with the given header value, so replay tests can
// reuse a header verbatim. body may be nil for bodyless requests.
func (c *e2eClient) send(t *testing.T, method, uri, headerValue string, body []byte) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+uri, rdr)
	require.NoError(t, err)
	req.Header.Set(authproof.Header, headerValue)
	if body != nil {
		req.Header.Set("Content-Type", handlers.ContentTypeOctetStream)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	payload, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	return resp, payload
}

// do signs and sends in one step — the honest-client path.
func (c *e2eClient) do(t *testing.T, method, uri string, body []byte) (*http.Response, []byte) {
	t.Helper()
	return c.send(t, method, uri, c.authHeader(t, method, uri, body), body)
}

type e2eAppendResult struct {
	Status string `json:"status"`
	Seq    int    `json:"seq"`
	Sha256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func (c *e2eClient) upload(t *testing.T, device string, seq int, body []byte) (*http.Response, e2eAppendResult) {
	t.Helper()
	uri := "/v1/log/" + device + "?seq=" + strconv.Itoa(seq) + "&generation=1"
	resp, payload := c.do(t, http.MethodPost, uri, body)
	var out e2eAppendResult
	// Tolerate non-JSON error bodies; callers assert on the status first.
	_ = json.Unmarshal(payload, &out)
	return resp, out
}

func (c *e2eClient) manifestDevices(t *testing.T) []blobstore.DeviceSummary {
	t.Helper()
	resp, payload := c.do(t, http.MethodGet, "/v1/manifest", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out struct {
		Devices []blobstore.DeviceSummary `json:"devices"`
	}
	require.NoError(t, json.Unmarshal(payload, &out))
	return out.Devices
}

func e2eSha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestLimitsIsUnauthenticatedAndPublishesTheKeyProofsVerifyAgainst(t *testing.T) {
	env, alice, _ := newE2E(t)

	// newE2E already fetched /v1/limits without a header; here the contents are pinned.
	require.Equal(t, "success", env.publishedLimits.Status)
	require.Equal(t, e2eMaxBlobBytes, env.publishedLimits.MaxBlobBytes)
	require.Equal(t, e2eMaxBlobBytes, env.publishedLimits.MaxBodyBytes,
		"the proof travels in a header, so body cap and blob cap must be the same number")
	require.Equal(t, env.walletKey, env.publishedKey,
		"/v1/limits published a different key than the server wallet holds")

	// The published key is the counterparty alice derived her signing key toward. If the
	// server verified against anything else, this request would be refused.
	resp, _ := alice.do(t, http.MethodGet, "/v1/manifest", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestUploadReportsTheStoredShaAndSize(t *testing.T) {
	_, alice, _ := newE2E(t)
	body := bytes.Repeat([]byte{0x5a}, 4<<10)

	resp, out := alice.upload(t, e2eAliceDevice, 1, body)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	require.Equal(t, "success", out.Status)
	require.Equal(t, 1, out.Seq)
	require.Equal(t, e2eSha256Hex(body), out.Sha256)
	require.Equal(t, int64(len(body)), out.Size)
}

func TestDownloadRoundTripsTheUploadedBytesExactly(t *testing.T) {
	_, alice, _ := newE2E(t)
	body := bytes.Repeat([]byte("ciphertext "), 400)

	resp, _ := alice.upload(t, e2eAliceDevice, 1, body)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	resp, got := alice.do(t, http.MethodGet, "/v1/log/"+e2eAliceDevice+"/1?generation=1", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, strconv.Itoa(len(body)), resp.Header.Get("Content-Length"),
		"Content-Length must be declared up front so restores can show progress")
	require.Equal(t, body, got)
}

func TestAnEightMiBBlobRoundTripsExactly(t *testing.T) {
	_, alice, _ := newE2E(t)

	// Random rather than repetitive, so a chunk stitched back in the wrong order or a
	// dropped boundary byte cannot cancel out.
	body := make([]byte, 8<<20)
	_, err := rand.Read(body)
	require.NoError(t, err)

	resp, out := alice.upload(t, e2eAliceDevice, 1, body)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	require.Equal(t, e2eSha256Hex(body), out.Sha256)
	require.Equal(t, int64(len(body)), out.Size)

	resp, got := alice.do(t, http.MethodGet, "/v1/log/"+e2eAliceDevice+"/1?generation=1", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, strconv.Itoa(len(body)), resp.Header.Get("Content-Length"))
	require.True(t, bytes.Equal(body, got), "downloaded bytes differ from what was uploaded")
}

func TestAnAppendAtTheWrongSequenceIsRefusedWithAConflict(t *testing.T) {
	_, alice, _ := newE2E(t)

	resp, _ := alice.upload(t, e2eAliceDevice, 1, []byte("first"))
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Skipping seq 2 would leave a silent hole in a restore; the server must refuse.
	resp, payload := alice.do(t, http.MethodPost,
		"/v1/log/"+e2eAliceDevice+"?seq=3&generation=1", []byte("third"))
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	require.Contains(t, string(payload), "ERR_SEQ_CONFLICT")
}

func TestOneTenantCannotReadAnothersBlobOrSeeItInTheManifest(t *testing.T) {
	_, alice, bob := newE2E(t)

	resp, _ := alice.upload(t, e2eAliceDevice, 1, []byte("alice-ciphertext"))
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Bob uses alice's exact coordinates with his own perfectly valid proof. The response
	// must be indistinguishable from the blob not existing.
	resp, payload := bob.do(t, http.MethodGet, "/v1/log/"+e2eAliceDevice+"/1?generation=1", nil)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	require.NotContains(t, string(payload), "alice-ciphertext")

	require.Empty(t, bob.manifestDevices(t), "bob's manifest listed devices he never wrote")
}

func TestAReplayedUploadHeaderIsRefused(t *testing.T) {
	_, alice, _ := newE2E(t)
	body := []byte("replayable ciphertext")
	uri := "/v1/log/" + e2eAliceDevice + "?seq=1&generation=1"
	header := alice.authHeader(t, http.MethodPost, uri, body)

	resp, _ := alice.send(t, http.MethodPost, uri, header, body)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Byte-identical request, still inside the validity window. Even the legitimate
	// sender must be refused: single-use nonces are what make a captured header worthless.
	resp, payload := alice.send(t, http.MethodPost, uri, header, body)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Contains(t, string(payload), "ERR_AUTH_REQUIRED")
}

func TestAnUploadWhoseBodyBetraysItsDigestStoresNothing(t *testing.T) {
	_, alice, _ := newE2E(t)
	uri := "/v1/log/" + e2eAliceDevice + "?seq=1&generation=1"

	// The proof signs one body's digest; the wire carries different bytes. The sender is
	// authenticated, so the refusal happens at EOF — and must leave no trace behind.
	header := alice.authHeader(t, http.MethodPost, uri, []byte("the signed body"))
	resp, payload := alice.send(t, http.MethodPost, uri, header, []byte("the actual body"))
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, string(payload), "ERR_BODY_DIGEST_MISMATCH")

	resp, payload = alice.do(t, http.MethodGet, "/v1/log/"+e2eAliceDevice+"?generation=1", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var idx struct {
		Entries []blobstore.Entry `json:"entries"`
	}
	require.NoError(t, json.Unmarshal(payload, &idx))
	require.Empty(t, idx.Entries, "a rejected upload left an entry in the log")
}

func TestAnOversizeUploadIsRefusedBeforeAuthenticationIsEvenAttempted(t *testing.T) {
	_, alice, _ := newE2E(t)

	// One byte over the cap and no auth header at all. A 401 here would mean the auth
	// layer ran first; the size guard owning the answer is what makes the 413 provable.
	body := bytes.Repeat([]byte{0x00}, int(e2eMaxBlobBytes)+1)
	req, err := http.NewRequest(http.MethodPost,
		alice.base+"/v1/log/"+e2eAliceDevice+"?seq=1&generation=1", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", handlers.ContentTypeOctetStream)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	payload, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	require.Contains(t, string(payload), "ERR_BLOB_TOO_LARGE")
}

func TestAnAuthenticatedChunkedUploadOverrunningTheCapMidStreamStoresNothing(t *testing.T) {
	_, alice, _ := newE2E(t)
	uri := "/v1/log/" + e2eAliceDevice + "?seq=1&generation=1"

	// The proof is genuine and binds a digest, but that digest can never be checked: the
	// body overruns the cap before EOF. This is the one oversize path the up-front
	// Content-Length check cannot catch — a chunked upload declares no length — so only
	// the mid-stream byte counting stands between an authenticated sender and unbounded
	// storage writes.
	header := alice.authHeader(t, http.MethodPost, uri, []byte("what the sender claimed it would upload"))

	// io.NopCloser over a LimitReader is none of the types net/http can take a length
	// from (*bytes.Reader, *bytes.Buffer, *strings.Reader), and ContentLength -1 makes
	// the chunked encoding explicit rather than inferred.
	body := io.NopCloser(io.LimitReader(rand.Reader, e2eMaxBlobBytes+16))
	req, err := http.NewRequest(http.MethodPost, alice.base+uri, body)
	require.NoError(t, err)
	req.ContentLength = -1
	req.Header.Set(authproof.Header, header)
	req.Header.Set("Content-Type", handlers.ContentTypeOctetStream)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	payload, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	require.Contains(t, string(payload), "ERR_BLOB_TOO_LARGE")
	// The size guard rewrites whatever the aborted handler answered; if that rewrite
	// dropped the CORS headers, a browser client would be forbidden from reading the very
	// refusal that tells it what went wrong.
	require.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"),
		"the mid-stream 413 lost its CORS headers")

	// The failed read aborted the store's transaction, so the sequence must look as if
	// the upload never happened — a leftover row would poison every future append.
	resp, payload = alice.do(t, http.MethodGet, "/v1/log/"+e2eAliceDevice+"?generation=1", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var idx struct {
		Entries []blobstore.Entry `json:"entries"`
	}
	require.NoError(t, json.Unmarshal(payload, &idx))
	require.Empty(t, idx.Entries, "an upload refused mid-stream left an entry in the log")
}

func TestDeleteAccountErasesTheCallerAndOnlyTheCaller(t *testing.T) {
	_, alice, bob := newE2E(t)
	bobBody := []byte("bob-ciphertext")

	resp, _ := alice.upload(t, e2eAliceDevice, 1, []byte("alice-ciphertext"))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp, _ = bob.upload(t, e2eBobDevice, 1, bobBody)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	resp, payload := alice.do(t, http.MethodDelete, "/v1/account", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var erased struct {
		Deleted int64 `json:"deleted"`
	}
	require.NoError(t, json.Unmarshal(payload, &erased))
	require.Equal(t, int64(1), erased.Deleted)

	// Alice's side is gone for good...
	require.Empty(t, alice.manifestDevices(t))
	resp, _ = alice.do(t, http.MethodGet, "/v1/log/"+e2eAliceDevice+"/1?generation=1", nil)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	// ...and bob never notices anything happened.
	devices := bob.manifestDevices(t)
	require.Len(t, devices, 1)
	require.Equal(t, e2eBobDevice, devices[0].DeviceID)
	resp, got := bob.do(t, http.MethodGet, "/v1/log/"+e2eBobDevice+"/1?generation=1", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, bobBody, got)
}
