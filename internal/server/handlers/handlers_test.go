package handlers_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/handlers"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/middlewares"
)

const testDevice = "0123456789abcdef0123456789abcdef"

// keyFor returns a deterministic public key for a test identity.
func keyFor(t *testing.T, n byte) *ec.PublicKey {
	t.Helper()
	b := make([]byte, 32)
	b[31] = n
	priv, pub := ec.PrivateKeyFromBytes(b)
	require.NotNil(t, priv)
	return pub
}

// routerFor builds the authenticated route table with a pre-injected identity, standing in
// for what the auth-proof middleware would place in the context.
func routerFor(store blobstore.BlobStore, identity *ec.PublicKey) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if identity != nil {
				req = req.WithContext(middlewares.WithIdentityKey(req.Context(), identity))
			}
			next.ServeHTTP(w, req)
		})
	})
	r.Get("/v1/manifest", handlers.Manifest(store))
	r.Post("/v1/log/{deviceId}", handlers.Append(store))
	r.Get("/v1/log/{deviceId}", handlers.Index(store))
	r.Get("/v1/log/{deviceId}/{seq}", handlers.Blob(store))
	r.Delete("/v1/generation/{deviceId}/{generation}", handlers.PruneGeneration(store))
	r.Delete("/v1/account", handlers.DeleteAccount(store))
	return r
}

func post(t *testing.T, h http.Handler, target string, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	return postBody(t, h, target, bytes.NewReader(body), contentType)
}

func postBody(t *testing.T, h http.Handler, target string, body io.Reader, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// seed appends payload directly to the store, hiding the streaming call shape from tests
// that only need data to exist.
func seed(t *testing.T, store blobstore.BlobStore, k blobstore.BlobKey, payload []byte) {
	t.Helper()
	_, _, err := store.Append(context.Background(), k, "", bytes.NewReader(payload))
	require.NoError(t, err)
}

// readBack fetches a blob directly from the store, checking the reported size against the
// stream it accompanies.
func readBack(t *testing.T, store blobstore.BlobStore, k blobstore.BlobKey) []byte {
	t.Helper()
	rc, size, err := store.Get(context.Background(), k)
	require.NoError(t, err)
	defer func() { require.NoError(t, rc.Close()) }()
	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.Equal(t, int64(len(data)), size)
	return data
}

// errAfterBody yields its bytes and then err in place of io.EOF — the exact shape the auth
// middleware's digest-verifying wrapper gives the store when the streamed bytes do not
// hash to the digest the proof signed.
type errAfterBody struct {
	r   io.Reader
	err error
}

func (b *errAfterBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if errors.Is(err, io.EOF) {
		return n, b.err
	}
	return n, err
}

func TestAppendRequiresAuthentication(t *testing.T) {
	h := routerFor(blobstore.NewMemoryStore(), nil)
	rec := post(t, h, "/v1/log/"+testDevice+"?seq=1&generation=1", []byte("x"), handlers.ContentTypeOctetStream)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_AUTH_REQUIRED")
}

func TestAppendRejectsNonOctetStream(t *testing.T) {
	h := routerFor(blobstore.NewMemoryStore(), keyFor(t, 1))
	rec := post(t, h, "/v1/log/"+testDevice+"?seq=1&generation=1", []byte("x"), "application/json")
	require.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
}

func TestAppendRejectsMalformedDeviceID(t *testing.T) {
	h := routerFor(blobstore.NewMemoryStore(), keyFor(t, 1))
	for _, bad := range []string{"NOTHEX", strings.Repeat("a", 31), strings.Repeat("A", 32)} {
		rec := post(t, h, "/v1/log/"+bad+"?seq=1&generation=1", []byte("x"), handlers.ContentTypeOctetStream)
		require.Equal(t, http.StatusBadRequest, rec.Code, "device id %q must be rejected", bad)
		require.Contains(t, rec.Body.String(), "ERR_INVALID_DEVICE_ID")
	}
}

func TestAppendStoresUnderTheAuthenticatedIdentity(t *testing.T) {
	// The security property of the whole service. There is no identity parameter to spoof,
	// so this asserts the handler takes the account from the context and nowhere else.
	store := blobstore.NewMemoryStore()
	identity := keyFor(t, 7)
	h := routerFor(store, identity)

	rec := post(t, h, "/v1/log/"+testDevice+"?seq=1&generation=1",
		[]byte("payload"), handlers.ContentTypeOctetStream)
	require.Equal(t, http.StatusCreated, rec.Code)

	got := readBack(t, store, blobstore.BlobKey{
		Pseudonym: identity.ToDERHex(), DeviceID: testDevice, Generation: 1, Seq: 1,
	})
	require.Equal(t, []byte("payload"), got)
}

func TestAppendReportsTheStoredShaAndSize(t *testing.T) {
	// The upload response is the client's end-to-end integrity check: it must echo the
	// sha256 and byte count of what the store actually kept, not what the client sent.
	h := routerFor(blobstore.NewMemoryStore(), keyFor(t, 2))
	payload := []byte("payload")

	rec := post(t, h, "/v1/log/"+testDevice+"?seq=1&generation=1", payload, handlers.ContentTypeOctetStream)
	require.Equal(t, http.StatusCreated, rec.Code)

	sum := sha256.Sum256(payload)
	body := rec.Body.String()
	require.Contains(t, body, `"status":"success"`)
	require.Contains(t, body, `"seq":1`)
	require.Contains(t, body, `"sha256":"`+hex.EncodeToString(sum[:])+`"`)
	require.Contains(t, body, `"size":`+strconv.Itoa(len(payload)))
}

func TestAppendRejectsASecondWriteToTheSameSequence(t *testing.T) {
	h := routerFor(blobstore.NewMemoryStore(), keyFor(t, 1))
	target := "/v1/log/" + testDevice + "?seq=1&generation=1"

	require.Equal(t, http.StatusCreated,
		post(t, h, target, []byte("first"), handlers.ContentTypeOctetStream).Code)

	rec := post(t, h, target, []byte("second"), handlers.ContentTypeOctetStream)
	require.Equal(t, http.StatusConflict, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_SEQ_CONFLICT")
}

func TestAppendRejectsEmptyBody(t *testing.T) {
	// The handler no longer pre-reads the body, so emptiness is detected by the store at
	// EOF; the mapping back to 400 ERR_EMPTY_BLOB is what this pins.
	h := routerFor(blobstore.NewMemoryStore(), keyFor(t, 1))
	rec := post(t, h, "/v1/log/"+testDevice+"?seq=1&generation=1", nil, handlers.ContentTypeOctetStream)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_EMPTY_BLOB")
}

func TestAppendKeepsNothingWhenTheBodyFailsItsDigest(t *testing.T) {
	// The auth middleware wraps upload bodies so a digest mismatch surfaces to the store
	// as a read error at EOF. The handler must translate that into the protocol's 400 and
	// the aborted append must leave no trace — a forged body costs the attacker an upload,
	// never storage.
	store := blobstore.NewMemoryStore()
	identity := keyFor(t, 5)
	h := routerFor(store, identity)

	body := &errAfterBody{r: strings.NewReader("forged payload"), err: middlewares.ErrBodyDigestMismatch}
	rec := postBody(t, h, "/v1/log/"+testDevice+"?seq=1&generation=1", body, handlers.ContentTypeOctetStream)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_BODY_DIGEST_MISMATCH")

	_, _, err := store.Get(context.Background(), blobstore.BlobKey{
		Pseudonym: identity.ToDERHex(), DeviceID: testDevice, Generation: 1, Seq: 1,
	})
	require.ErrorIs(t, err, blobstore.ErrNotFound)
}

func TestBlobReturnsRawBytes(t *testing.T) {
	store := blobstore.NewMemoryStore()
	identity := keyFor(t, 3)
	payload := []byte{0x00, 0xff, 0x10, 0x7f, 0x80}
	seed(t, store, blobstore.BlobKey{
		Pseudonym: identity.ToDERHex(), DeviceID: testDevice, Generation: 1, Seq: 1,
	}, payload)

	rec := httptest.NewRecorder()
	routerFor(store, identity).ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/v1/log/"+testDevice+"/1?generation=1", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, handlers.ContentTypeOctetStream, rec.Header().Get("Content-Type"))
	// Announced up front from the metadata row so a restoring client can show progress.
	require.Equal(t, strconv.Itoa(len(payload)), rec.Header().Get("Content-Length"))
	require.Equal(t, payload, rec.Body.Bytes())
}

func TestManifestEncodesEmptyArrayNotNull(t *testing.T) {
	rec := httptest.NewRecorder()
	routerFor(blobstore.NewMemoryStore(), keyFor(t, 1)).ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/v1/manifest", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"devices":[]`)
	require.NotContains(t, rec.Body.String(), "null")
}

// del issues a DELETE against the router under test.
func del(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestDeleteAccountRequiresAuthentication(t *testing.T) {
	// Erasure is the one irreversible operation here. An unauthenticated caller must not be
	// able to reach the store at all.
	store := blobstore.NewMemoryStore()
	seed(t, store, blobstore.BlobKey{
		Pseudonym: keyFor(t, 1).ToDERHex(), DeviceID: testDevice, Generation: 1, Seq: 1,
	}, []byte("x"))

	rec := del(t, routerFor(store, nil), "/v1/account")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_AUTH_REQUIRED")

	got := readBack(t, store, blobstore.BlobKey{
		Pseudonym: keyFor(t, 1).ToDERHex(), DeviceID: testDevice, Generation: 1, Seq: 1,
	})
	require.Equal(t, []byte("x"), got, "an unauthenticated request must not have erased anything")
}

func TestDeleteAccountErasesOnlyTheCallersData(t *testing.T) {
	ctx := context.Background()
	store := blobstore.NewMemoryStore()
	mine, theirs := keyFor(t, 1), keyFor(t, 2)

	for _, k := range []*ec.PublicKey{mine, theirs} {
		seed(t, store, blobstore.BlobKey{
			Pseudonym: k.ToDERHex(), DeviceID: testDevice, Generation: 1, Seq: 1,
		}, []byte("x"))
	}

	rec := del(t, routerFor(store, mine), "/v1/account")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"deleted":1`)

	_, _, err := store.Get(ctx, blobstore.BlobKey{
		Pseudonym: mine.ToDERHex(), DeviceID: testDevice, Generation: 1, Seq: 1,
	})
	require.ErrorIs(t, err, blobstore.ErrNotFound)

	// The account address comes from the authenticated identity and nowhere else, so one
	// caller can never name another's pseudonym.
	got := readBack(t, store, blobstore.BlobKey{
		Pseudonym: theirs.ToDERHex(), DeviceID: testDevice, Generation: 1, Seq: 1,
	})
	require.Equal(t, []byte("x"), got)
}

func TestDeleteAccountRemovesTheRetainedWindowToo(t *testing.T) {
	ctx := context.Background()
	store := blobstore.NewMemoryStore()
	mine := keyFor(t, 3)
	for gen := 1; gen <= 3; gen++ {
		seed(t, store, blobstore.BlobKey{
			Pseudonym: mine.ToDERHex(), DeviceID: testDevice, Generation: gen, Seq: 1,
		}, []byte("x"))
	}

	// What PruneGeneration refuses (409 ERR_RETENTION_GUARD on the two newest) is exactly
	// what an erasure request has to remove, which is why this endpoint exists at all.
	require.Equal(t, http.StatusConflict,
		del(t, routerFor(store, mine), "/v1/generation/"+testDevice+"/3").Code)

	rec := del(t, routerFor(store, mine), "/v1/account")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"deleted":3`)

	devices, err := store.Manifest(ctx, mine.ToDERHex())
	require.NoError(t, err)
	require.Empty(t, devices)
}

func TestDeleteAccountIsIdempotentOverHTTP(t *testing.T) {
	// A client that never saw the first response must be able to retry without getting an
	// error it would have to interpret.
	store := blobstore.NewMemoryStore()
	h := routerFor(store, keyFor(t, 4))

	require.Equal(t, http.StatusOK, del(t, h, "/v1/account").Code)
	rec := del(t, h, "/v1/account")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"deleted":0`)
}
