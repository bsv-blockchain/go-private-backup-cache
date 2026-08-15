package handlers

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/responses"
)

// DefaultIndexLimit bounds an index page.
const DefaultIndexLimit = 500

// Manifest handles GET /v1/manifest — every device and generation for the caller.
//
// This is the entry point for restore: a fresh install derives its pseudonym from the
// recovered seed, calls this, and picks a device and generation to replay.
func Manifest(store blobstore.BlobStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		account := pseudonym(w, r)
		if account == "" {
			return
		}

		devices, err := store.Manifest(r.Context(), account)
		if err != nil {
			responses.WriteError(w, http.StatusInternalServerError, "ERR_INTERNAL", "Could not read the manifest.")
			return
		}
		if devices == nil {
			devices = []blobstore.DeviceSummary{} // never encode null
		}
		responses.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "devices": devices})
	}
}

// Index handles GET /v1/log/{deviceId}?generation=&from=&limit=
func Index(store blobstore.BlobStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		account := pseudonym(w, r)
		if account == "" {
			return
		}
		device, ok := deviceID(w, chi.URLParam(r, "deviceId"))
		if !ok {
			return
		}
		generation, genOK := positiveIntParam(r, "generation")
		if !genOK {
			responses.WriteError(w, http.StatusBadRequest,
				"ERR_INVALID_PARAMS", "Query parameter generation must be a positive integer.")
			return
		}

		from := optionalIntParam(r, "from", 1)
		limit := optionalIntParam(r, "limit", DefaultIndexLimit)
		if limit < 1 || limit > DefaultIndexLimit {
			limit = DefaultIndexLimit
		}

		entries, err := store.Index(r.Context(), account, device, generation, from, limit)
		if err != nil {
			responses.WriteError(w, http.StatusInternalServerError, "ERR_INTERNAL", "Could not read the log index.")
			return
		}
		if entries == nil {
			entries = []blobstore.Entry{}
		}
		responses.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "entries": entries})
	}
}

// Blob handles GET /v1/log/{deviceId}/{seq}?generation=
//
// Responds with raw ciphertext. The client's AuthFetch rebuilds the body as a Uint8Array,
// so binary needs no encoding on the way back — unlike upload.
func Blob(store blobstore.BlobStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		account := pseudonym(w, r)
		if account == "" {
			return
		}
		device, ok := deviceID(w, chi.URLParam(r, "deviceId"))
		if !ok {
			return
		}
		generation, genOK := positiveIntParam(r, "generation")
		seq, seqOK := parsePathInt(chi.URLParam(r, "seq"))
		if !genOK || !seqOK {
			responses.WriteError(w, http.StatusBadRequest,
				"ERR_INVALID_PARAMS", "Sequence and generation must be positive integers.")
			return
		}

		data, err := store.Get(r.Context(), blobstore.BlobKey{
			Pseudonym: account, DeviceID: device, Generation: generation, Seq: seq,
		})
		switch {
		case errors.Is(err, blobstore.ErrNotFound):
			// Identical response whether the blob is absent or belongs to someone else.
			responses.WriteError(w, http.StatusNotFound, "ERR_BLOB_NOT_FOUND", "No such blob.")
		case err != nil:
			responses.WriteError(w, http.StatusInternalServerError, "ERR_INTERNAL", "Could not read the blob.")
		default:
			w.Header().Set("Content-Type", ContentTypeOctetStream)
			w.WriteHeader(http.StatusOK)
			if _, werr := w.Write(data); werr != nil {
				slog.Error("failed to write blob body", "error", werr)
			}
		}
	}
}

func parsePathInt(raw string) (int, bool) {
	n := 0
	if raw == "" {
		return 0, false
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 0, false
		}
	}
	if n < 1 {
		return 0, false
	}
	return n, true
}
