package handlers

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/middlewares"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/responses"
)

// ContentTypeOctetStream is the only accepted upload encoding. Raw binary rather than
// base64-in-JSON — there is no base64 fallback by design.
const ContentTypeOctetStream = "application/octet-stream"

// Append handles POST /v1/log/{deviceId}?seq=&generation=&prevSha256=
//
// The body STREAMS into the store: by the time this handler runs, the auth middleware has
// verified the sender from the proof header alone and wrapped the body so it fails at EOF
// if the bytes do not hash to the digest the proof signed. A mismatch or an oversize read
// error aborts the store's transaction — nothing is kept from a bad upload.
func Append(store blobstore.BlobStore) http.HandlerFunc {
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

		// The account comes from auth, never from the request.
		key := blobstore.BlobKey{
			Pseudonym:  account,
			DeviceID:   device,
			Generation: generation,
			Seq:        seq,
		}

		sha, size, err := store.Append(r.Context(), key, r.URL.Query().Get("prevSha256"), r.Body)
		switch {
		case errors.Is(err, blobstore.ErrSeqConflict):
			responses.WriteError(w, http.StatusConflict, "ERR_SEQ_CONFLICT", err.Error())
		case errors.Is(err, blobstore.ErrEmptyBlob):
			responses.WriteError(w, http.StatusBadRequest, "ERR_EMPTY_BLOB", "Blob must not be empty.")
		case errors.Is(err, middlewares.ErrBodyDigestMismatch):
			responses.WriteError(w, http.StatusBadRequest, "ERR_BODY_DIGEST_MISMATCH",
				"Body does not hash to the digest the auth proof signed. Nothing was stored.")
		case err != nil:
			// An oversize body also lands here as a read error, but the size guard owns
			// that response and rewrites this one into the 413.
			responses.WriteError(w, http.StatusInternalServerError, "ERR_INTERNAL", "Could not store the blob.")
		default:
			responses.WriteJSON(w, http.StatusCreated, map[string]any{
				"status": "success",
				"seq":    seq,
				"sha256": sha,
				"size":   size,
			})
		}
	}
}
