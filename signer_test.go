package signer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type serviceVector struct {
	Name      string  `json:"name"`
	Request   Request `json:"request"`
	Key       string  `json:"key_hex"`
	Signature string  `json:"signature_hex"`
	SignedTx  string  `json:"signed_tx_hex"`
}

func vectors(t *testing.T) []serviceVector {
	t.Helper()
	b, e := os.ReadFile("testdata/service-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var v []serviceVector
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func TestServiceCompatibility(t *testing.T) {
	for _, v := range vectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			key, _ := hex.DecodeString(v.Key)
			before := bytes.Clone(key)
			out, e := Sign(v.Request, key)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(key, before) {
				t.Fatal("modified caller key")
			}
			if v.Signature != "" && out.SignatureHex != v.Signature {
				t.Fatalf("signature differs from wallet-service: %s", out.SignatureHex)
			}
			sig, _ := hex.DecodeString(out.SignatureHex)
			pub, _ := hex.DecodeString(out.PublicKeyHex)
			digest, _ := hex.DecodeString(out.DigestHex)
			switch out.Algorithm {
			case "ed25519":
				msg := digest
				if v.Request.Family == Solana {
					msg, _ = hex.DecodeString(v.Request.PayloadHex)
				}
				if !ed25519.Verify(pub, msg, sig) {
					t.Fatal("invalid Ed25519 signature")
				}
			case "secp256k1-der":
				p, e := btcec.ParsePubKey(pub)
				if e != nil {
					t.Fatal(e)
				}
				s, e := ecdsa.ParseDERSignature(sig)
				if e != nil || !s.Verify(digest, p) {
					t.Fatal("invalid DER signature")
				}
			case "secp256k1-rsv":
				p, e := crypto.SigToPub(digest, sig)
				if e != nil || !bytes.Equal(crypto.CompressPubkey(p), pub) {
					t.Fatal("invalid recovery signature")
				}
			}
			if v.SignedTx != "" {
				unsigned, _ := hex.DecodeString(v.Request.PayloadHex)
				var tx types.Transaction
				if e = tx.UnmarshalBinary(unsigned); e != nil {
					t.Fatal(e)
				}
				signed, e := tx.WithSignature(types.LatestSignerForChainID(big.NewInt(1)), sig)
				if e != nil {
					t.Fatal(e)
				}
				b, e := signed.MarshalBinary()
				if e != nil {
					t.Fatal(e)
				}
				if "0x"+hex.EncodeToString(b) != v.SignedTx {
					t.Fatal("signed bytes differ from wallet-service")
				}
			}
		})
	}
}

func TestRejectInvalidRequests(t *testing.T) {
	base := vectors(t)[0].Request
	key := make([]byte, 32)
	key[31] = 1
	tests := []struct {
		name string
		edit func(*Request)
	}{
		{"version", func(r *Request) { r.Version = 2 }},
		{"family", func(r *Request) { r.Family = "UNKNOWN" }},
		{"short digest", func(r *Request) { r.PayloadHex = "00" }},
		{"odd hex", func(r *Request) { r.PayloadHex = "123" }},
		{"bad hex", func(r *Request) { r.PayloadHex = "gg" }},
		{"prefix", func(r *Request) { r.PayloadHex = "0x" + r.PayloadHex }},
		{"empty", func(r *Request) { r.PayloadHex = "" }},
		{"oversize", func(r *Request) { r.PayloadHex = strings.Repeat("00", MaxPayloadBytes+1) }},
		{"hash type", func(r *Request) { r.HashType = 257 }},
		{"missing hash type", func(r *Request) { r.HashType = 0 }},
		{"extra chain id", func(r *Request) { r.ChainID = "1" }},
		{"solana digest", func(r *Request) { r.Family = Solana; r.HashType = 0 }},
		{"invalid boc", func(r *Request) { r.Family = TON; r.HashType = 0; r.PayloadType = TONCell }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := base
			tt.edit(&r)
			if s, e := Sign(r, key); e == nil || s.SignatureHex != "" {
				t.Fatal("accepted invalid request")
			}
		})
	}
	for _, k := range [][]byte{nil, make([]byte, 31), make([]byte, 32), bytes.Repeat([]byte{255}, 32), make([]byte, 33)} {
		if _, e := Sign(base, k); e == nil {
			t.Fatal("accepted invalid scalar")
		}
	}
}

func TestEd25519KeyValidation(t *testing.T) {
	var r Request
	for _, v := range vectors(t) {
		if v.Request.Family == Solana {
			r = v.Request
		}
	}
	seed := bytes.Repeat([]byte{32}, 32)
	key := ed25519.NewKeyFromSeed(seed)
	a, e := Sign(r, seed)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Sign(r, key)
	if e != nil || a.SignatureHex != b.SignatureHex {
		t.Fatal("seed/full mismatch")
	}
	key[63] ^= 1
	if _, e = Sign(r, key); e == nil {
		t.Fatal("accepted inconsistent key")
	}
}

func TestBatch(t *testing.T) {
	v := vectors(t)[0]
	key, _ := hex.DecodeString(v.Key)
	out, e := SignBatch([]Request{v.Request, v.Request}, key)
	if e != nil || len(out) != 2 || out[0].SignatureHex != v.Signature {
		t.Fatal("batch mismatch")
	}
	bad := v.Request
	bad.Version = 0
	if out, e = SignBatch([]Request{v.Request, bad}, key); e == nil || out != nil {
		t.Fatal("partial batch result")
	}
	if _, e = SignBatch(nil, key); e == nil {
		t.Fatal("empty batch accepted")
	}
}

func TestTestnetFamilies(t *testing.T) {
	aliases := map[Family]Family{BTC: BTCTestnet, LTC: LTCTestnet, BCH: BCHTestnet, DOGE: DOGETestnet, XRP: XRPTestnet}
	for _, v := range vectors(t) {
		alias, ok := aliases[v.Request.Family]
		if !ok {
			continue
		}
		key, _ := hex.DecodeString(v.Key)
		r := v.Request
		r.Family = alias
		out, err := Sign(r, key)
		if err != nil || out.SignatureHex != v.Signature || out.Family != alias {
			t.Fatalf("testnet alias %s: %v", alias, err)
		}
	}
}

func TestEVMValidation(t *testing.T) {
	for _, v := range vectors(t) {
		if v.Request.Family != EVM {
			continue
		}
		key, _ := hex.DecodeString(v.Key)
		for _, id := range []string{"", "0", "-1", "0x1", " 1", "+1"} {
			r := v.Request
			r.ChainID = id
			if _, e := Sign(r, key); e == nil {
				t.Fatalf("accepted id %q", id)
			}
		}
		r := v.Request
		r.PayloadHex = strings.TrimPrefix(v.SignedTx, "0x")
		if _, e := Sign(r, key); e == nil {
			t.Fatal("accepted signed EVM tx")
		}
		if v.Name == "evm-1559" {
			r = v.Request
			r.ChainID = "2"
			if _, e := Sign(r, key); e == nil {
				t.Fatal("accepted wrong chain")
			}
		}
	}
}

func FuzzSign(f *testing.F) {
	f.Add([]byte{1, 2, 3}, uint8(0))
	families := []Family{EVM, BTC, LTC, BCH, DOGE, TRON, TON, XRP, Solana}
	f.Fuzz(func(t *testing.T, b []byte, index uint8) {
		key := make([]byte, 32)
		key[31] = 1
		fam := families[int(index)%len(families)]
		kind := Digest
		switch fam {
		case EVM:
			kind = EVMTransaction
		case TON:
			kind = TONCell
		case TRON:
			kind = TRONRawData
		case XRP:
			kind = XRPBlob
		case Solana:
			kind = SolanaMessage
		}
		r := Request{Version: 1, Family: fam, PayloadType: kind, PayloadHex: hex.EncodeToString(b)}
		if fam == EVM {
			r.ChainID = "1"
		}
		if fam == BTC || fam == LTC || fam == DOGE {
			r.HashType = 1
		}
		if fam == BCH {
			r.HashType = 65
		}
		_, _ = Sign(r, key)
	})
}
