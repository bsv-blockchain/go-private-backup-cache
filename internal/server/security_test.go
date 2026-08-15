package server_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/handlers"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/middlewares"
)

// This suite exists because a sibling project shipped exactly this bug: its storage sync
// routes trusted an identity supplied in the request body instead of binding it to the
// authenticated peer, letting any authenticated caller read or overwrite another user's
// wallet data.
//
// If any test here fails, that is a real cross-tenant vulnerability. Fix the handler, never
// the test.

const secDevice = "abcdefabcdefabcdefabcdefabcdefab"

func identityFor(t *testing.T, n byte) *ec.PublicKey {
	t.Helper()
	b := make([]byte, 32)
	b[31] = n
	_, pub := ec.PrivateKeyFromBytes(b)
	return pub
}

func routerAs(store blobstore.BlobStore, identity *ec.PublicKey) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(middlewares.WithIdentityKey(req.Context(), identity)))
		})
	})
	r.Get("/v1/manifest", handlers.Manifest(store))
	r.Post("/v1/log/{deviceId}", handlers.Append(store, 1<<20))
	r.Get("/v1/log/{deviceId}", handlers.Index(store))
	r.Get("/v1/log/{deviceId}/{seq}", handlers.Blob(store))
	r.Delete("/v1/generation/{deviceId}/{generation}", handlers.PruneGeneration(store))
	return r
}

func seedAlice(t *testing.T, store blobstore.BlobStore, alice *ec.PublicKey) {
	t.Helper()
	_, err := store.Append(context.Background(), blobstore.BlobKey{
		Pseudonym: alice.ToDERHex(), DeviceID: secDevice, Generation: 1, Seq: 1,
	}, "", []byte("alice-secret-ciphertext"))
	require.NoError(t, err)
}

func TestNoReadRouteLeaksAcrossIdentities(t *testing.T) {
	store := blobstore.NewMemoryStore()
	alice := identityFor(t, 1)
	bob := identityFor(t, 2)
	seedAlice(t, store, alice)

	// Bob asks for Alice's data using her exact device id, generation and sequence. Every
	// route must behave as though it does not exist.
	cases := []struct{ name, method, path string }{
		{"manifest", http.MethodGet, "/v1/manifest"},
		{"index", http.MethodGet, "/v1/log/" + secDevice + "?generation=1"},
		{"blob", http.MethodGet, "/v1/log/" + secDevice + "/1?generation=1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			routerAs(store, bob).ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))

			require.NotContains(t, rec.Body.String(), "alice-secret",
				"%s leaked another identity's ciphertext", tc.name)
			require.NotContains(t, rec.Body.String(), alice.ToDERHex(),
				"%s leaked another identity's pseudonym", tc.name)
		})
	}
}

func TestBlobForAnotherIdentityIsIndistinguishableFromMissing(t *testing.T) {
	store := blobstore.NewMemoryStore()
	alice := identityFor(t, 1)
	bob := identityFor(t, 2)
	seedAlice(t, store, alice)

	existing := httptest.NewRecorder()
	routerAs(store, bob).ServeHTTP(existing,
		httptest.NewRequest(http.MethodGet, "/v1/log/"+secDevice+"/1?generation=1", nil))

	absent := httptest.NewRecorder()
	routerAs(store, bob).ServeHTTP(absent,
		httptest.NewRequest(http.MethodGet, "/v1/log/"+secDevice+"/9?generation=1", nil))

	// Identical responses, so the API cannot be used to probe for another user's blobs.
	require.Equal(t, http.StatusNotFound, existing.Code)
	require.Equal(t, absent.Code, existing.Code)
	require.Equal(t, absent.Body.String(), existing.Body.String())
}

func TestAppendCannotWriteIntoAnotherIdentitysLog(t *testing.T) {
	store := blobstore.NewMemoryStore()
	alice := identityFor(t, 1)
	bob := identityFor(t, 2)
	seedAlice(t, store, alice)

	// Same device and generation as Alice. Bob's write must land in Bob's own log, and
	// must not disturb Alice's entry at the same coordinates.
	req := httptest.NewRequest(http.MethodPost,
		"/v1/log/"+secDevice+"?seq=1&generation=1", bytes.NewReader([]byte("bob-wrote-this")))
	req.Header.Set("Content-Type", handlers.ContentTypeOctetStream)
	rec := httptest.NewRecorder()
	routerAs(store, bob).ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	aliceBlob, err := store.Get(context.Background(), blobstore.BlobKey{
		Pseudonym: alice.ToDERHex(), DeviceID: secDevice, Generation: 1, Seq: 1,
	})
	require.NoError(t, err)
	require.Equal(t, []byte("alice-secret-ciphertext"), aliceBlob,
		"another identity's write overwrote this identity's blob")

	bobBlob, err := store.Get(context.Background(), blobstore.BlobKey{
		Pseudonym: bob.ToDERHex(), DeviceID: secDevice, Generation: 1, Seq: 1,
	})
	require.NoError(t, err)
	require.Equal(t, []byte("bob-wrote-this"), bobBlob)
}

func TestPruneCannotDeleteAnotherIdentitysData(t *testing.T) {
	store := blobstore.NewMemoryStore()
	alice := identityFor(t, 1)
	bob := identityFor(t, 2)

	// Give Alice three generations so generation 1 would be prunable by her.
	for gen := 1; gen <= 3; gen++ {
		_, err := store.Append(context.Background(), blobstore.BlobKey{
			Pseudonym: alice.ToDERHex(), DeviceID: secDevice, Generation: gen, Seq: 1,
		}, "", []byte("alice-secret-ciphertext"))
		require.NoError(t, err)
	}

	rec := httptest.NewRecorder()
	routerAs(store, bob).ServeHTTP(rec,
		httptest.NewRequest(http.MethodDelete, "/v1/generation/"+secDevice+"/1", nil))
	require.Equal(t, http.StatusNotFound, rec.Code)

	// Alice's data survives untouched.
	_, err := store.Get(context.Background(), blobstore.BlobKey{
		Pseudonym: alice.ToDERHex(), DeviceID: secDevice, Generation: 1, Seq: 1,
	})
	require.NoError(t, err, "another identity deleted this identity's generation")
}

func TestManifestOnlyEverListsTheCallersOwnDevices(t *testing.T) {
	store := blobstore.NewMemoryStore()
	alice := identityFor(t, 1)
	bob := identityFor(t, 2)
	seedAlice(t, store, alice)

	_, err := store.Append(context.Background(), blobstore.BlobKey{
		Pseudonym: bob.ToDERHex(), DeviceID: "ffffffffffffffffffffffffffffffff", Generation: 1, Seq: 1,
	}, "", []byte("bob-ciphertext"))
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	routerAs(store, bob).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/manifest", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "ffffffffffffffffffffffffffffffff")
	require.NotContains(t, rec.Body.String(), secDevice, "manifest leaked another identity's device")
}
