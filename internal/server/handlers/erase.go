package handlers

import (
	"net/http"

	"github.com/bsv-blockchain/go-private-backup-cache/internal/blobstore"
	"github.com/bsv-blockchain/go-private-backup-cache/internal/server/responses"
)

// DeleteAccount handles DELETE /v1/account
//
// Erasure on request: every blob belonging to the authenticated pseudonym, across all
// devices and all generations, removed for good. This is the GDPR Article 17 path, and it
// is deliberately a separate route from PruneGeneration rather than a flag on it:
//
//   - Pruning serves compaction and therefore REFUSES the two newest generations, so a
//     client bug cannot destroy the only recoverable backup. Erasure must remove exactly
//     those, so the retention guard cannot apply.
//   - The blast radius differs by an order of magnitude, and a route that can only ever do
//     one of the two is easier to reason about than a parameter that switches between them.
//
// Authorisation is structural rather than administrative. The pseudonym comes from the
// authenticated identity alone (see the pseudonym helper), so the only party who can erase
// an account is whoever holds the key it derives from — which is also the only party who
// could ever prove the account was theirs, since the service stores nothing else about it.
// There is no operator override, and there is nothing here for one to act on: the blobs are
// opaque ciphertext and the account address is a pseudonym.
//
// Idempotent by design: erasing an account that holds nothing returns 200 with a count of
// zero. A client whose first response was lost in transit must be able to retry without
// having to interpret an error, and "already erased" is the outcome it wanted.
func DeleteAccount(store blobstore.BlobStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		account := pseudonym(w, r)
		if account == "" {
			return
		}

		n, err := store.DeleteAccount(r.Context(), account)
		if err != nil {
			responses.WriteError(w, http.StatusInternalServerError,
				"ERR_INTERNAL", "Could not erase the account.")
			return
		}

		// The count is reported so a client can tell the user what was actually removed,
		// and so an erasure that found nothing is distinguishable from one that found data
		// — without either being an error.
		responses.WriteJSON(w, http.StatusOK, map[string]any{"deleted": n})
	}
}
