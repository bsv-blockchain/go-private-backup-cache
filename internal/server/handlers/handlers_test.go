package handlers_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/handlers"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/middlewares"
)

const (
	testDevice   = "0123456789abcdef0123456789abcdef"
	testMaxBytes = 1 << 20
)

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
// for what the BRC-103/104 middleware would place in the context.
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
	r.Post("/v1/log/{deviceId}", handlers.Append(store, testMaxBytes))
	r.Get("/v1/log/{deviceId}", handlers.Index(store))
	r.Get("/v1/log/{deviceId}/{seq}", handlers.Blob(store))
	r.Delete("/v1/generation/{deviceId}/{generation}", handlers.PruneGeneration(store))
	return r
}

func post(t *testing.T, h http.Handler, target string, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
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

func TestAppendRejectsOversizeBlob(t *testing.T) {
	h := routerFor(blobstore.NewMemoryStore(), keyFor(t, 1))
	rec := post(t, h, "/v1/log/"+testDevice+"?seq=1&generation=1",
		make([]byte, testMaxBytes+1), handlers.ContentTypeOctetStream)
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_BLOB_TOO_LARGE")
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

	got, err := store.Get(context.Background(), blobstore.BlobKey{
		Pseudonym: identity.ToDERHex(), DeviceID: testDevice, Generation: 1, Seq: 1,
	})
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), got)
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
	h := routerFor(blobstore.NewMemoryStore(), keyFor(t, 1))
	rec := post(t, h, "/v1/log/"+testDevice+"?seq=1&generation=1", nil, handlers.ContentTypeOctetStream)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_EMPTY_BLOB")
}

func TestBlobReturnsRawBytes(t *testing.T) {
	store := blobstore.NewMemoryStore()
	identity := keyFor(t, 3)
	payload := []byte{0x00, 0xff, 0x10, 0x7f, 0x80}
	_, err := store.Append(context.Background(), blobstore.BlobKey{
		Pseudonym: identity.ToDERHex(), DeviceID: testDevice, Generation: 1, Seq: 1,
	}, "", payload)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	routerFor(store, identity).ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/v1/log/"+testDevice+"/1?generation=1", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, handlers.ContentTypeOctetStream, rec.Header().Get("Content-Type"))
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
