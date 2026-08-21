package client_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkwallet "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-private-backup-cache/client"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/authproof"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/nonce"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server"
)

const (
	testDevice   = "0123456789abcdef0123456789abcdef"
	testMaxBytes = int64(1 << 20)
)

// newTestServer runs the REAL router — auth middleware, size guard, handlers — so every
// assertion below covers the whole wire protocol, not a client-side mock of it.
func newTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	w, err := sdkwallet.NewCompletedProtoWallet(priv)
	require.NoError(t, err)

	h, err := server.NewRouter(server.Deps{
		Wallet:       w,
		Store:        blobstore.NewMemoryStore(),
		Nonces:       nonce.NewMemoryStore(),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxBlobBytes: testMaxBytes,
	})
	require.NoError(t, err)

	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, priv.PubKey().ToDERHex()
}

func newTestClient(t *testing.T, ts *httptest.Server) *client.Client {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	return client.New(ts.URL, priv)
}

func randomPayload(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestLimitsReportsTheServersIdentityKeyAndCap(t *testing.T) {
	ts, serverKey := newTestServer(t)
	c := newTestClient(t, ts)

	lim, err := c.Limits(context.Background())
	require.NoError(t, err)
	require.Equal(t, serverKey, lim.ServerIdentityKey)
	require.Equal(t, testMaxBytes, lim.MaxBlobBytes)
	require.Equal(t, testMaxBytes, lim.MaxBodyBytes)
}

func TestAppendBytesAndBlobRoundTripByteExact(t *testing.T) {
	ts, _ := newTestServer(t)
	c := newTestClient(t, ts)
	ctx := context.Background()
	payload := randomPayload(t, 4096)

	res, err := c.AppendBytes(ctx, testDevice, 1, 1, "", payload)
	require.NoError(t, err)
	require.Equal(t, 1, res.Seq)
	require.Equal(t, sha256Hex(payload), res.Sha256,
		"the server's hash of what it stored must match the client's hash of what it sent")
	require.Equal(t, int64(len(payload)), res.Size)

	body, size, err := c.Blob(ctx, testDevice, 1, 1)
	require.NoError(t, err)
	defer func() { require.NoError(t, body.Close()) }()
	require.Equal(t, int64(len(payload)), size, "Content-Length must be known up front")

	got, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

func TestAppendStreamsFromAPlainReaderWithAPrecomputedDigest(t *testing.T) {
	ts, _ := newTestServer(t)
	c := newTestClient(t, ts)
	ctx := context.Background()
	payload := randomPayload(t, 64<<10)

	// Wrapping strips the concrete type so net/http cannot sniff a length or seek back —
	// the client must work from the caller's digest and size alone, as it would for a
	// blob far too large to buffer.
	body := struct{ io.Reader }{bytes.NewReader(payload)}

	res, err := c.Append(ctx, testDevice, 1, 1, "", body, sha256Hex(payload), int64(len(payload)))
	require.NoError(t, err)
	require.Equal(t, sha256Hex(payload), res.Sha256)
	require.Equal(t, int64(len(payload)), res.Size)

	got, size, err := c.Blob(ctx, testDevice, 1, 1)
	require.NoError(t, err)
	defer func() { require.NoError(t, got.Close()) }()
	require.Equal(t, int64(len(payload)), size)
	round, err := io.ReadAll(got)
	require.NoError(t, err)
	require.Equal(t, payload, round)
}

func TestIndexAndManifestAgreeOnTheLogHead(t *testing.T) {
	ts, _ := newTestServer(t)
	c := newTestClient(t, ts)
	ctx := context.Background()

	var prev string
	var total int64
	shas := make([]string, 0, 3)
	for seq := 1; seq <= 3; seq++ {
		payload := randomPayload(t, 100*seq)
		res, err := c.AppendBytes(ctx, testDevice, 1, seq, prev, payload)
		require.NoError(t, err)
		prev = res.Sha256
		total += res.Size
		shas = append(shas, res.Sha256)
	}

	entries, err := c.Index(ctx, testDevice, 1, 0, 0)
	require.NoError(t, err)
	require.Len(t, entries, 3)
	for i, e := range entries {
		require.Equal(t, i+1, e.Seq)
		require.Equal(t, shas[i], e.Sha256)
		if i > 0 {
			require.Equal(t, shas[i-1], e.PrevSha256, "entries must chain by digest")
		}
	}

	devices, err := c.Manifest(ctx)
	require.NoError(t, err)
	require.Len(t, devices, 1)
	require.Equal(t, testDevice, devices[0].DeviceID)
	require.Equal(t, 1, devices[0].Generation)
	require.Equal(t, 3, devices[0].HeadSeq)
	require.Equal(t, shas[2], devices[0].HeadSha256, "the manifest head must be the last indexed entry")
	require.Equal(t, total, devices[0].TotalBytes)
}

func TestASeqConflictSurfacesAsATypedAPIError(t *testing.T) {
	ts, _ := newTestServer(t)
	c := newTestClient(t, ts)
	ctx := context.Background()

	_, err := c.AppendBytes(ctx, testDevice, 1, 1, "", []byte("first"))
	require.NoError(t, err)

	_, err = c.AppendBytes(ctx, testDevice, 1, 1, "", []byte("second"))
	var apiErr *client.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, 409, apiErr.Status)
	require.Equal(t, "ERR_SEQ_CONFLICT", apiErr.Code)
}

func TestAWrongBodyDigestIsRefusedAndNothingIsStored(t *testing.T) {
	ts, _ := newTestServer(t)
	c := newTestClient(t, ts)
	ctx := context.Background()
	payload := []byte("actual bytes")

	// The proof signs the digest of DIFFERENT bytes; the server only discovers the lie
	// after streaming the body, and must keep none of it.
	_, err := c.Append(ctx, testDevice, 1, 1, "",
		bytes.NewReader(payload), sha256Hex([]byte("claimed bytes")), int64(len(payload)))
	var apiErr *client.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, 400, apiErr.Status)
	require.Equal(t, "ERR_BODY_DIGEST_MISMATCH", apiErr.Code)

	_, _, err = c.Blob(ctx, testDevice, 1, 1)
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, "ERR_BLOB_NOT_FOUND", apiErr.Code, "the refused upload must not have been kept")
}

func TestDeleteAccountErasesEverythingAndIsIdempotent(t *testing.T) {
	ts, _ := newTestServer(t)
	c := newTestClient(t, ts)
	ctx := context.Background()

	_, err := c.AppendBytes(ctx, testDevice, 1, 1, "", []byte("kept until erased"))
	require.NoError(t, err)

	deleted, err := c.DeleteAccount(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted)

	devices, err := c.Manifest(ctx)
	require.NoError(t, err)
	require.Empty(t, devices)

	// A retry after a lost response must succeed with a zero count, not error.
	deleted, err = c.DeleteAccount(ctx)
	require.NoError(t, err)
	require.Zero(t, deleted)
}

func TestAnotherIdentityCannotReadTheBlob(t *testing.T) {
	// The isolation property of the whole service: the account is the caller's key, so a
	// different key is a different universe — indistinguishable from an empty one.
	ts, _ := newTestServer(t)
	owner := newTestClient(t, ts)
	stranger := newTestClient(t, ts)
	ctx := context.Background()

	_, err := owner.AppendBytes(ctx, testDevice, 1, 1, "", []byte("private"))
	require.NoError(t, err)

	_, _, err = stranger.Blob(ctx, testDevice, 1, 1)
	var apiErr *client.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, 404, apiErr.Status)
	require.Equal(t, "ERR_BLOB_NOT_FOUND", apiErr.Code)

	devices, err := stranger.Manifest(ctx)
	require.NoError(t, err)
	require.Empty(t, devices, "the owner's device must not appear in a stranger's manifest")
}

// spentProofServer fakes only the replay guard's refusal path: every authed request's
// proof header is recorded, and the first refuseFirst of them are answered with the exact
// 401 envelope the real guard sends when a transparent keep-alive re-send delivers an
// already-spent proof. A fake rather than the real router because the real guard can only
// refuse a proof it has genuinely seen twice — which net/http's resend logic produces only
// on a torn-down connection, not reproducibly in a test.
func spentProofServer(t *testing.T, refuseFirst int) (*httptest.Server, func() []string) {
	t.Helper()
	serverPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverKey := serverPriv.PubKey().ToDERHex()

	var mu sync.Mutex
	var proofs []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/limits" {
			_, _ = fmt.Fprintf(w, `{"maxBlobBytes":%d,"maxBodyBytes":%d,"serverIdentityKey":%q}`,
				testMaxBytes, testMaxBytes, serverKey)
			return
		}
		mu.Lock()
		proofs = append(proofs, r.Header.Get(authproof.Header))
		attempt := len(proofs)
		mu.Unlock()
		if attempt <= refuseFirst {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"status":"error","code":"ERR_AUTH_REQUIRED","description":"Authentication required: proof already used."}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"success","devices":[]}`))
	}))
	t.Cleanup(ts.Close)

	return ts, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), proofs...)
	}
}

func TestABodylessRequestReSignsOnceWhenItsProofWasSpentByATransparentResend(t *testing.T) {
	ts, seenProofs := spentProofServer(t, 1)
	c := newTestClient(t, ts)

	devices, err := c.Manifest(context.Background())
	require.NoError(t, err, "the freshly signed second attempt must succeed")
	require.Empty(t, devices)

	proofs := seenProofs()
	require.Len(t, proofs, 2, "exactly one retry, no more")
	require.NotEmpty(t, proofs[0])
	require.NotEqual(t, proofs[0], proofs[1],
		"the retry must carry a freshly signed proof, not the byte-identical header a transport resend would")
}

func TestAPersistentSpentProofRefusalSurfacesAfterASingleRetry(t *testing.T) {
	// A server that refuses fresh proofs as spent is broken or hostile; the client must
	// not loop against it.
	ts, seenProofs := spentProofServer(t, 1_000_000)
	c := newTestClient(t, ts)

	_, err := c.Manifest(context.Background())
	var apiErr *client.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusUnauthorized, apiErr.Status)
	require.Equal(t, "ERR_AUTH_REQUIRED", apiErr.Code)
	require.Len(t, seenProofs(), 2, "one retry and then the refusal must surface")
}

func TestAppendNeverRetriesASpentProof(t *testing.T) {
	// A spent Append proof means the first copy may already have stored the entry, so a
	// re-signed retry could double-append; the refusal must reach the caller untouched.
	ts, seenProofs := spentProofServer(t, 1_000_000)
	c := newTestClient(t, ts)

	_, err := c.AppendBytes(context.Background(), testDevice, 1, 1, "", []byte("payload"))
	var apiErr *client.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusUnauthorized, apiErr.Status)
	require.Equal(t, "ERR_AUTH_REQUIRED", apiErr.Code)
	require.Len(t, seenProofs(), 1, "an upload must reach the wire exactly once")
}

func TestPruneGenerationRespectsTheRetentionGuard(t *testing.T) {
	ts, _ := newTestServer(t)
	c := newTestClient(t, ts)
	ctx := context.Background()

	for gen := 1; gen <= 3; gen++ {
		_, err := c.AppendBytes(ctx, testDevice, gen, 1, "", []byte{byte(gen)})
		require.NoError(t, err)
	}

	// The newest two generations are the recoverable window and must be refused.
	err := c.PruneGeneration(ctx, testDevice, 3)
	var apiErr *client.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, "ERR_RETENTION_GUARD", apiErr.Code)

	require.NoError(t, c.PruneGeneration(ctx, testDevice, 1))

	_, _, err = c.Blob(ctx, testDevice, 1, 1)
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, "ERR_BLOB_NOT_FOUND", apiErr.Code)
}
