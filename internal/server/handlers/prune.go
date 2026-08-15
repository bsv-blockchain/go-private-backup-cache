package handlers

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/responses"
)

// PruneGeneration handles DELETE /v1/generation/{deviceId}/{generation}
//
// Compaction is client-driven: the client writes a fresh full snapshot as generation N+1
// and then asks for an old generation to be dropped. The server refuses to delete anything
// inside the retained window, so a client bug cannot destroy the only recoverable backup.
//
// There is deliberately no time-based expiry anywhere in this service. A pseudonym that has
// not been written to for years belongs to precisely the user this service exists for:
// someone who lost their device and has not yet replaced it.
func PruneGeneration(store blobstore.BlobStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		account := pseudonym(w, r)
		if account == "" {
			return
		}
		device, ok := deviceID(w, chi.URLParam(r, "deviceId"))
		if !ok {
			return
		}
		generation, genOK := parsePathInt(chi.URLParam(r, "generation"))
		if !genOK {
			responses.WriteError(w, http.StatusBadRequest,
				"ERR_INVALID_PARAMS", "Generation must be a positive integer.")
			return
		}

		n, err := store.DeleteGeneration(r.Context(), account, device, generation)
		switch {
		case errors.Is(err, blobstore.ErrRetentionGuard):
			responses.WriteError(w, http.StatusConflict, "ERR_RETENTION_GUARD", err.Error())
		case err != nil:
			responses.WriteError(w, http.StatusInternalServerError, "ERR_INTERNAL", "Could not prune the generation.")
		case n == 0:
			responses.WriteError(w, http.StatusNotFound, "ERR_GENERATION_NOT_FOUND", "No such generation.")
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}
}
