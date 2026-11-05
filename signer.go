package signer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type Family string

const (
	EVM         Family = "EVM"
	BTC         Family = "BTC_UTXO"
	LTC         Family = "LITECOIN_UTXO"
	BCH         Family = "BTC_CASH_UTXO"
	DOGE        Family = "DOGECOIN_UTXO"
	TRON        Family = "TRON"
	TON         Family = "TON"
	XRP         Family = "XRP_LEDGER"
	Solana      Family = "SOLANA"
	BTCTestnet  Family = "BTC_UTXO_TESTNET"
	LTCTestnet  Family = "LITECOIN_UTXO_TESTNET"
	BCHTestnet  Family = "BTC_CASH_UTXO_TESTNET"
	DOGETestnet Family = "DOGECOIN_UTXO_TESTNET"
	XRPTestnet  Family = "XRP_LEDGER_TESTNET"
)

type PayloadType string

const (
	// EVMTransaction is an unsigned binary legacy or EIP-1559 transaction.
	EVMTransaction PayloadType = "evm_transaction"
	// Digest is an already computed 32-byte signing digest. Not valid for Solana or EVM.
	Digest        PayloadType = "digest"
	TRONRawData   PayloadType = "tron_raw_data"
	TONCell       PayloadType = "ton_cell"
	XRPBlob       PayloadType = "xrp_blob"
	SolanaMessage PayloadType = "solana_message"
)

// Request contains only public data prepared by Crypto Chief. PayloadHex is even-length
// hex without a prefix. One UTXO input requires one request. Version must be 1.
// Testnets use the same Family; network-specific parameters are already in the payload.
type Request struct {
	Version     int         `json:"version"`
	Family      Family      `json:"chain_family"`
	PayloadType PayloadType `json:"payload_type"`
	PayloadHex  string      `json:"payload_hex"`
	ChainID     string      `json:"chain_id,omitempty"`  // EVM only; mandatory positive decimal
	HashType    uint32      `json:"hash_type,omitempty"` // UTXO only: 1; BCH: 65
}

// Signature contains only a signature and its public verification data, never a
// transaction or key. R||S||V uses V=0/1. UTXO DER excludes the hash-type byte;
// WithHashTypeHex includes it. Solana signs the exact message, not its SHA-256 hash.
type Signature struct {
	Version         int    `json:"version"`
	Family          Family `json:"chain_family"`
	Algorithm       string `json:"algorithm"`
	PublicKeyHex    string `json:"public_key_hex"`
	SignatureHex    string `json:"signature_hex"`
	SignatureBase64 string `json:"signature_base64"`
	DigestHex       string `json:"digest_hex,omitempty"`
	WithHashTypeHex string `json:"signature_with_hashtype_hex,omitempty"`
}

const MaxPayloadBytes = 1024 * 1024

// MaxBatchPayloadBytes bounds aggregate decoded payload size before any signature is produced.
const MaxBatchPayloadBytes = 8 * 1024 * 1024

func prepareSigningRequest(req Request) (family Family, payload, digest []byte, err error) {
	switch req.Family {
	case BTCTestnet:
		req.Family = BTC
	case LTCTestnet:
		req.Family = LTC
	case BCHTestnet:
		req.Family = BCH
	case DOGETestnet:
		req.Family = DOGE
	case XRPTestnet:
		req.Family = XRP
	}
	if req.Version != 1 {
		return "", nil, nil, errors.New("unsupported request version")
	}
	if len(req.PayloadHex) == 0 || len(req.PayloadHex) > MaxPayloadBytes*2 {
		return "", nil, nil, errors.New("payload is empty or too large")
	}
	payload, err = hex.DecodeString(req.PayloadHex)
	if err != nil {
		return "", nil, nil, errors.New("payload_hex must be even-length hex without a prefix")
	}
	if req.Family != EVM && req.ChainID != "" {
		return "", nil, nil, errors.New("chain_id is only valid for EVM")
	}
	utxo := req.Family == BTC || req.Family == LTC || req.Family == BCH || req.Family == DOGE
	if !utxo && req.HashType != 0 {
		return "", nil, nil, errors.New("hash_type is only valid for UTXO")
	}
	switch req.Family {
	case EVM:
		if req.PayloadType != EVMTransaction {
			return "", nil, nil, errors.New("EVM requires evm_transaction")
		}
		digest, err = evmDigest(payload, req.ChainID)
	case BTC, LTC, BCH, DOGE:
		if req.PayloadType != Digest || len(payload) != 32 {
			return "", nil, nil, errors.New("UTXO requires a 32-byte sighash digest")
		}
		want := uint32(1)
		if req.Family == BCH {
			want = 0x41
		}
		if req.HashType != want {
			return "", nil, nil, fmt.Errorf("hash_type must be %d for this family", want)
		}
		digest = payload
	case TRON:
		switch req.PayloadType {
		case TRONRawData:
			h := sha256.Sum256(payload)
			digest = h[:]
		case Digest:
			digest, err = exactDigest(payload)
		default:
			err = errors.New("TRON requires tron_raw_data or digest")
		}
	case XRP:
		switch req.PayloadType {
		case XRPBlob:
			h := sha512.New()
			h.Write([]byte{0x53, 0x54, 0x58, 0})
			h.Write(payload)
			digest = h.Sum(nil)[:32]
		case Digest:
			digest, err = exactDigest(payload)
		default:
			err = errors.New("XRP requires xrp_blob or digest")
		}
	case TON:
		switch req.PayloadType {
		case TONCell:
			digest, err = tonCellDigest(payload)
		case Digest:
			digest, err = exactDigest(payload)
		default:
			err = errors.New("TON requires ton_cell or digest")
		}
	case Solana:
		if req.PayloadType != SolanaMessage {
			return "", nil, nil, errors.New("Solana requires solana_message, not a digest")
		}
	default:
		return "", nil, nil, errors.New("unsupported family")
	}
	if err != nil {
		return "", nil, nil, fmt.Errorf("invalid signing payload: %w", err)
	}
	return req.Family, payload, digest, nil
}

// ValidateRequest performs the same payload validation as Sign without using a key.
func ValidateRequest(req Request) error {
	_, _, _, err := prepareSigningRequest(req)
	return err
}

// Sign uses a raw 32-byte secp256k1 key or Ed25519 seed. TON/Solana also accept
// a consistent 64-byte Ed25519 private key. No key encoding is guessed or repaired.
// The caller owns its key buffer. Sign neither stores nor modifies it.
func Sign(req Request, privateKey []byte) (Signature, error) {
	var zero Signature
	requestedFamily := req.Family
	family, payload, digest, err := prepareSigningRequest(req)
	if err != nil {
		return zero, err
	}
	req.Family = family
	utxo := family == BTC || family == LTC || family == BCH || family == DOGE
	var sig, pub []byte
	var algo string
	if req.Family == TON || req.Family == Solana {
		key, e := edKey(privateKey)
		if e != nil {
			return zero, e
		}
		defer clear(key)
		msg := digest
		if req.Family == Solana {
			msg = payload
		}
		sig = ed25519.Sign(key, msg)
		pub = key.Public().(ed25519.PublicKey)
		algo = "ed25519"
	} else {
		// ToECDSA rejects zero, overflow and wrong lengths instead of reducing mod N.
		key, e := crypto.ToECDSA(privateKey)
		if e != nil {
			return zero, errors.New("invalid secp256k1 private key: expected a valid 32-byte scalar")
		}
		defer func() { clear(key.D.Bits()); key.D.SetInt64(0) }()
		pub = crypto.CompressPubkey(&key.PublicKey)
		if req.Family == EVM || req.Family == TRON {
			sig, err = crypto.Sign(digest, key)
			algo = "secp256k1-rsv"
		} else {
			k, _ := btcec.PrivKeyFromBytes(privateKey)
			sig = ecdsa.Sign(k, digest).Serialize()
			k.Zero()
			algo = "secp256k1-der"
		}
		if err != nil {
			return zero, errors.New("signing failed")
		}
	}
	out := Signature{Version: 1, Family: requestedFamily, Algorithm: algo, PublicKeyHex: hex.EncodeToString(pub),
		SignatureHex: hex.EncodeToString(sig), SignatureBase64: base64.StdEncoding.EncodeToString(sig), DigestHex: hex.EncodeToString(digest)}
	if utxo {
		out.WithHashTypeHex = hex.EncodeToString(append(append([]byte{}, sig...), byte(req.HashType)))
	}
	return out, nil
}

// SignBatch signs several prepared inputs atomically at the API level: an invalid
// item returns no signatures. All items use the supplied key; order is preserved.
func SignBatch(requests []Request, privateKey []byte) ([]Signature, error) {
	if len(requests) == 0 || len(requests) > 4096 {
		return nil, errors.New("batch must contain 1..4096 items")
	}
	total := 0
	for i, req := range requests {
		if len(req.PayloadHex) > MaxPayloadBytes*2 || len(req.PayloadHex)%2 != 0 {
			return nil, fmt.Errorf("item %d: invalid payload length", i)
		}
		total += len(req.PayloadHex) / 2
		if total > MaxBatchPayloadBytes {
			return nil, errors.New("batch payload limit exceeded")
		}
	}
	out := make([]Signature, len(requests))
	for i, req := range requests {
		sig, err := Sign(req, privateKey)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		out[i] = sig
	}
	return out, nil
}

func exactDigest(b []byte) ([]byte, error) {
	if len(b) != 32 {
		return nil, errors.New("digest must be exactly 32 bytes")
	}
	return b, nil
}

func edKey(b []byte) (ed25519.PrivateKey, error) {
	if len(b) != 32 && len(b) != 64 {
		return nil, errors.New("Ed25519 key must be a 32-byte seed or 64-byte private key")
	}
	k := ed25519.NewKeyFromSeed(b[:32])
	if len(b) == 64 && !bytes.Equal(b, k) {
		clear(k)
		return nil, errors.New("inconsistent Ed25519 private key")
	}
	return k, nil
}

func evmDigest(payload []byte, chain string) ([]byte, error) {
	if len(chain) == 0 || len(chain) > 78 || (len(chain) > 1 && chain[0] == '0') {
		return nil, errors.New("chain_id must be a canonical positive decimal integer of at most 256 bits")
	}
	id, ok := new(big.Int).SetString(chain, 10)
	if !ok || id.Sign() <= 0 || id.BitLen() > 256 || strings.Trim(chain, "0123456789") != "" {
		return nil, errors.New("chain_id must be a positive decimal integer of at most 256 bits")
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(payload); err != nil {
		return nil, errors.New("invalid unsigned EVM transaction")
	}
	if tx.Type() != types.LegacyTxType && tx.Type() != types.DynamicFeeTxType {
		return nil, errors.New("only legacy and EIP-1559 transactions are supported")
	}
	v, r, s := tx.RawSignatureValues()
	if v.Sign() != 0 || r.Sign() != 0 || s.Sign() != 0 {
		return nil, errors.New("EVM transaction must be unsigned")
	}
	if tx.Type() == types.DynamicFeeTxType && tx.ChainId().Cmp(id) != 0 {
		return nil, errors.New("EVM chain_id mismatch")
	}
	if tx.Gas() == 0 || tx.GasFeeCap().BitLen() > 256 || tx.GasTipCap().Cmp(tx.GasFeeCap()) > 0 || tx.Value().BitLen() > 256 {
		return nil, errors.New("invalid EVM gas or value")
	}
	return types.LatestSignerForChainID(id).Hash(&tx).Bytes(), nil
}
