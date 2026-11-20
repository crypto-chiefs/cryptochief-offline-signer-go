package signer

import (
	"bytes"
	"encoding/hex"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// EVM and TRON both derive a 20-byte account identifier from a secp256k1 key.
func accountID(publicKeyHex string) (common.Address, error) {
	raw, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return common.Address{}, ErrSender
	}
	key, err := crypto.DecompressPubkey(raw)
	if err != nil {
		return common.Address{}, ErrSender
	}
	return crypto.PubkeyToAddress(*key), nil
}

func inspectEVM(payload []byte, wallet Wallet) ([]Transfer, error) {
	var tx types.Transaction
	if tx.UnmarshalBinary(payload) != nil {
		return nil, ErrMalformed
	}
	id, err := accountID(wallet.PublicKeyHex)
	if err != nil || !common.IsHexAddress(wallet.Address) || common.HexToAddress(wallet.Address) != id {
		return nil, ErrSender
	}
	if tx.To() == nil {
		return nil, ErrUnsupported
	}
	// An unsigned EVM transaction has no sender field. The selected signing
	// wallet determines its sender; chain_id is covered by RequestDigest.
	t := Transfer{From: wallet.Address, To: tx.To().Hex(), AmountAtomic: tx.Value().String(), Asset: Asset{Kind: "native"}}
	t.FeeLimitAtomic = new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas()), tx.GasFeeCap()).String()
	if len(tx.Data()) != 0 {
		to, amount, err := decodeTokenTransfer(tx.Data())
		if err != nil {
			return nil, err
		}
		if tx.Value().Sign() != 0 {
			return nil, ErrUnsupported
		}
		t.Asset = Asset{Kind: "token", Contract: tx.To().Hex()}
		t.To, t.AmountAtomic = common.BytesToAddress(to).Hex(), amount
	}
	return []Transfer{t}, nil
}

// Direct transfer(address,uint256) in the Ethereum and TRON ABIs.
func decodeTokenTransfer(data []byte) ([]byte, string, error) {
	if len(data) != 68 || !bytes.Equal(data[:4], []byte{0xa9, 0x05, 0x9c, 0xbb}) {
		return nil, "", ErrUnsupported
	}
	var padding [12]byte
	if !bytes.Equal(data[4:16], padding[:]) {
		return nil, "", ErrMalformed
	}
	return data[16:36], new(big.Int).SetBytes(data[36:68]).String(), nil
}
