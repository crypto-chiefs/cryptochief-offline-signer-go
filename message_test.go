package signer

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// Constants copied from transaction-service f3c0209,
// internal/chains/tron/message_sign_convention_test.go.
func TestTRONMessageServiceVectors(t *testing.T) {
	for _, tt := range []struct{ message, digest string }{
		{"0x68656c6c6f", "14c21f3ca5d9ad0888621cc86b4a2fc6be6353b294780944e06c1c912e0cb95c"},
		{"hello", "a07d8e5b946cc0416662f5420751673680809e5f10313e20c7c5badb0ef4226d"},
	} {
		digest, err := TRONMessageDigest(tt.message, TRONPrefixV2)
		if err != nil || hex.EncodeToString(digest[:]) != tt.digest {
			t.Fatalf("service digest mismatch: %v", err)
		}
	}
}

func TestTRONMessagePrefixAndLength(t *testing.T) {
	message := "Привет\n"
	v2, err := TRONMessageDigest(message, TRONPrefixV2)
	if err != nil {
		t.Fatal(err)
	}
	// UTF-8 bytes, not code points: 6 Cyrillic letters and a newline = 13 bytes.
	wantV2 := crypto.Keccak256([]byte("\x19TRON Signed Message:\n13Привет\n"))
	if !bytes.Equal(v2[:], wantV2) {
		t.Fatal("v2 used wrong byte length or transformed message")
	}
	legacy, err := TRONMessageDigest(message, TRONPrefixLegacy32)
	if err != nil {
		t.Fatal(err)
	}
	wantLegacy := crypto.Keccak256([]byte("\x19TRON Signed Message:\n32Привет\n"))
	if !bytes.Equal(legacy[:], wantLegacy) || v2 == legacy {
		t.Fatal("wrong legacy32 prefix")
	}
	if _, err = TRONMessageDigest(strings.Repeat("a", 512), TRONPrefixV2); err != nil {
		t.Fatal(err)
	}
	if _, err = TRONMessageDigest("\tlogin\r\n", TRONPrefixV2); err != nil {
		t.Fatal(err)
	}
}

func TestSignTRONMessage(t *testing.T) {
	key := make([]byte, 32)
	key[31] = 1
	before := bytes.Clone(key)
	for _, mode := range []string{TRONPrefixV2, TRONPrefixLegacy32} {
		signed, err := SignTRONMessage("hello", mode, key)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := TRONMessageDigest("hello", mode)
		if err != nil {
			t.Fatal(err)
		}
		if signed.DigestHex != hex.EncodeToString(digest[:]) || signed.Family != TRON || signed.Algorithm != "secp256k1-rsv" {
			t.Fatal("incorrect signature metadata")
		}
		sig, err := hex.DecodeString(signed.SignatureHex)
		if err != nil || len(sig) != 65 || sig[64] > 1 {
			t.Fatal("invalid recoverable signature format")
		}
		pub, err := crypto.SigToPub(digest[:], sig)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(crypto.CompressPubkey(pub)) != "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" {
			t.Fatal("signature recovers a different key")
		}
		other, err := TRONMessageDigest("0x68656c6c6f", mode)
		if err != nil {
			t.Fatal(err)
		}
		if crypto.VerifySignature(crypto.CompressPubkey(pub), other[:], sig[:64]) {
			t.Fatal("literal and hex-looking message signatures collide")
		}
	}
	if !bytes.Equal(key, before) {
		t.Fatal("caller key was modified")
	}
}

func TestRejectInvalidTRONMessages(t *testing.T) {
	key := make([]byte, 32)
	key[31] = 1
	for _, message := range []string{"", " \t\n", "before\x00after", "bell\x07", "zero\u200bwidth", strings.Repeat("a", 513), string([]byte{0xff})} {
		if sig, err := SignTRONMessage(message, TRONPrefixV2, key); err == nil || sig.SignatureHex != "" {
			t.Fatal("accepted invalid message")
		}
	}
	for _, mode := range []string{"", "v3", "V2", " v2"} {
		if sig, err := SignTRONMessage("hello", mode, key); err == nil || sig.SignatureHex != "" {
			t.Fatal("accepted invalid prefix mode")
		}
	}
	if sig, err := SignTRONMessage("hello", TRONPrefixV2, nil); err == nil || sig.SignatureHex != "" {
		t.Fatal("accepted invalid key")
	}
}
