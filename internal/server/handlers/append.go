package handlers

import (
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/responses"
)

// ContentTypeOctetStream is the only accepted upload encoding.
//
// Raw binary rather than base64-in-JSON. This requires @bsv/sdk 2.4.0 on the client: 2.1.9's
// AuthFetch tested `typeof body === 'object'` ahead of its binary branches, so a Uint8Array
// body was JSON-stringified into {"0":12,...}. There is no base64 fallback by design.
const ContentTypeOctetStream = "application/octet-stream"

// Append handles POST /v1/log/{deviceId}?seq=&generation=&prevSha256=
func Append(store blobstore.BlobStore, maxBytes int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		account := pseudonym(w, r)
		if account == "" {
			return
		}

		if ct := r.Header.Get("Content-Type"); ct != ContentTypeOctetStream {
			responses.WriteError(w, http.StatusUnsupportedMediaType,
				"ERR_UNSUPPORTED_MEDIA_TYPE", "Body must be application/octet-stream.")
			return
		}

		device, ok := deviceID(w, chi.URLParam(r, "deviceId"))
		if !ok {
			return
		}

		seq, seqOK := positiveIntParam(r, "seq")
		generation, genOK := positiveIntParam(r, "generation")
		if !seqOK || !genOK {
			responses.WriteError(w, http.StatusBadRequest,
				"ERR_INVALID_PARAMS", "Query parameters seq and generation must be positive integers.")
			return
		}

		// Bounded read. Streaming is impossible behind the auth middleware, so the body is
		// fully buffered either way; reading one byte past the cap is how oversize is
		// detected without trusting a client-declared length.
		data, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
		if err != nil {
			responses.WriteError(w, http.StatusBadRequest, "ERR_BODY_READ", "Could not read the request body.")
			return
		}
		if int64(len(data)) > maxBytes {
			responses.WriteError(w, http.StatusRequestEntityTooLarge,
				"ERR_BLOB_TOO_LARGE", "Blob exceeds the maximum permitted size.")
			return
		}
		if len(data) == 0 {
			responses.WriteError(w, http.StatusBadRequest, "ERR_EMPTY_BLOB", "Blob must not be empty.")
			return
		}

		// The account comes from auth, never from the request.
		key := blobstore.BlobKey{
			Pseudonym:  account,
			DeviceID:   device,
			Generation: generation,
			Seq:        seq,
		}

		sha, err := store.Append(r.Context(), key, r.URL.Query().Get("prevSha256"), data)
		switch {
		case errors.Is(err, blobstore.ErrSeqConflict):
			responses.WriteError(w, http.StatusConflict, "ERR_SEQ_CONFLICT", err.Error())
		case err != nil:
			responses.WriteError(w, http.StatusInternalServerError, "ERR_INTERNAL", "Could not store the blob.")
		default:
			responses.WriteJSON(w, http.StatusCreated, map[string]any{
				"status": "success",
				"seq":    seq,
				"sha256": sha,
			})
		}
	}
}
