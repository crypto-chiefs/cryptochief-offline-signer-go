package signer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/xssnick/tonutils-go/address"
)

func TestWalletServiceAddressCompatibility(t *testing.T) {
	var vectors []struct {
		Family    Family `json:"chain_family"`
		Key       string `json:"key_hex"`
		Address   string `json:"address"`
		PublicKey string `json:"public_key_hex"`
	}
	b, err := os.ReadFile("testdata/wallet-service-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 28 {
		t.Fatalf("expected 28 service address vectors; got %d", len(vectors))
	}
	for _, v := range vectors {
		t.Run(string(v.Family)+"/"+v.Key[62:], func(t *testing.T) {
			key, _ := hex.DecodeString(v.Key)
			before := bytes.Clone(key)
			w, err := DeriveWallet(WalletOptions{Family: v.Family}, key)
			if err != nil {
				t.Fatal(err)
			}
			if w.Address != v.Address || w.PublicKeyHex != v.PublicKey || w.Family != v.Family {
				t.Fatalf("wallet differs from service: %+v", w)
			}
			if !bytes.Equal(before, key) {
				t.Fatal("modified caller's key")
			}
		})
	}
}

func TestGenerateWalletAllFamilies(t *testing.T) {
	families := []Family{EVM, TRON, TON, Solana, XRP, XRPTestnet, BTC, BTCTestnet, LTC, LTCTestnet, BCH, BCHTestnet, DOGE, DOGETestnet}
	for _, family := range families {
		t.Run(string(family), func(t *testing.T) {
			o := WalletOptions{Family: family}
			w, key, err := GenerateWallet(o)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(key)
			if len(key) != 32 {
				t.Fatal("wrong generated key length")
			}
			derived, err := DeriveWallet(o, key)
			if err != nil || !reflect.DeepEqual(w, derived) {
				t.Fatal("key does not derive generated public record")
			}
			other, otherKey, err := GenerateWallet(o)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(otherKey)
			if other.Address == w.Address || bytes.Equal(key, otherKey) {
				t.Fatal("repeated generated key")
			}
			publicJSON, err := json.Marshal(w)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(publicJSON, []byte(hex.EncodeToString(key))) || bytes.Contains(publicJSON, []byte("private")) {
				t.Fatal("public record contains secret")
			}
			if w.PublicKeyHex == "" || w.Address == "" || w.AddressType == "" {
				t.Fatal("incomplete public record")
			}
			// A locally generated key must also sign using the same public key.
			for _, v := range vectors(t) {
				r := v.Request
				baseFamily := family
				switch family {
				case XRPTestnet:
					baseFamily = XRP
				case BTCTestnet:
					baseFamily = BTC
				case LTCTestnet:
					baseFamily = LTC
				case BCHTestnet:
					baseFamily = BCH
				case DOGETestnet:
					baseFamily = DOGE
				}
				if r.Family != baseFamily {
					continue
				}
				r.Family = family
				sig, err := Sign(r, key)
				if err != nil {
					t.Fatal(err)
				}
				if sig.PublicKeyHex != w.PublicKeyHex {
					t.Fatal("generation and signer public keys differ")
				}
				break
			}
		})
	}
}

func TestWalletRejectsInvalidInputs(t *testing.T) {
	valid := make([]byte, 32)
	valid[31] = 1
	for _, o := range []WalletOptions{{}, {Family: "unknown"}, {Family: BTC, TONTestnet: true}, {Family: TRON, TONNonBounceable: true}} {
		if w, key, err := GenerateWallet(o); err == nil || key != nil || w.Address != "" {
			t.Fatal("accepted invalid wallet options")
		}
		if w, err := DeriveWallet(o, valid); err == nil || w.Address != "" {
			t.Fatal("derived invalid wallet options")
		}
	}
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 32), make([]byte, 33), bytes.Repeat([]byte{255}, 32)} {
		if w, err := DeriveWallet(WalletOptions{Family: EVM}, key); err == nil || w.Address != "" {
			t.Fatal("accepted invalid secp256k1 key")
		}
	}
	for _, family := range []Family{TON, Solana} {
		seed := bytes.Repeat([]byte{0x20}, 32)
		full := ed25519.NewKeyFromSeed(seed)
		a, err := DeriveWallet(WalletOptions{Family: family}, seed)
		if err != nil {
			t.Fatal(err)
		}
		b, err := DeriveWallet(WalletOptions{Family: family}, full)
		if err != nil || a != b {
			t.Fatal("seed/full private key differs")
		}
		full[63] ^= 1
		if _, err = DeriveWallet(WalletOptions{Family: family}, full); err == nil {
			t.Fatal("accepted inconsistent Ed25519 key")
		}
	}
}

func TestTONAddressFlags(t *testing.T) {
	key := make([]byte, 32)
	key[31] = 1
	var raw string
	for _, testnet := range []bool{false, true} {
		for _, nonBounce := range []bool{false, true} {
			w, err := DeriveWallet(WalletOptions{Family: TON, TONTestnet: testnet, TONNonBounceable: nonBounce}, key)
			if err != nil {
				t.Fatal(err)
			}
			a, err := address.ParseAddr(w.Address)
			if err != nil {
				t.Fatal(err)
			}
			if a.IsTestnetOnly() != testnet || a.IsBounceable() == nonBounce {
				t.Fatal("TON address flags mismatch")
			}
			if raw == "" {
				raw = a.StringRaw()
			}
			if a.StringRaw() != raw {
				t.Fatal("TON display flags changed account ID")
			}
			if w.TONSubwalletID != 698983191 || w.AddressType != "v4r2" {
				t.Fatal("incorrect TON wallet parameters")
			}
		}
	}
}
