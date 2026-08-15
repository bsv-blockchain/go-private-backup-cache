// Package wallet builds the server's own BSV identity.
package wallet

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkwallet "github.com/bsv-blockchain/go-sdk/wallet"
)

// NewServerIdentity builds a key-only wallet for BRC-103/104 mutual auth.
//
// CompletedProtoWallet has no storage, no UTXOs and no chain access. That is deliberate
// and load-bearing: this service never transacts, and a wallet that cannot spend cannot be
// drained if the host is compromised.
//
// It is also why the BRC-105 payment middleware must never be attached — its code path
// dereferences the result of InternalizeAction, which this wallet returns as nil.
func NewServerIdentity(hexKey string) (sdkwallet.Interface, error) {
	priv, err := ec.PrivateKeyFromHex(hexKey)
	if err != nil {
		return nil, fmt.Errorf("parse server key: %w", err)
	}
	w, err := sdkwallet.NewCompletedProtoWallet(priv)
	if err != nil {
		return nil, fmt.Errorf("build server wallet: %w", err)
	}
	return w, nil
}
