package signer

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/xssnick/tonutils-go/tvm/cell"
)

func TestTONSigningBOCValidation(t *testing.T) {
	key := make([]byte, 32)
	key[31] = 1
	leaf := cell.BeginCell().MustStoreUInt(42, 6).EndCell()
	root := cell.BeginCell().MustStoreUInt(698983191, 32).
		MustStoreUInt(2000000000, 32).MustStoreUInt(7, 32).
		MustStoreUInt(0, 8).MustStoreUInt(3, 8).MustStoreRef(leaf).EndCell()
	request := func(b []byte) Request {
		return Request{Version: 1, Family: TON, PayloadType: TONCell, PayloadHex: hex.EncodeToString(b)}
	}
	baseline, err := Sign(Request{Version: 1, Family: TON, PayloadType: Digest, PayloadHex: hex.EncodeToString(root.Hash())}, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, flags := range [][]bool{{false}, {true}, {false, true}, {true, true}} {
		boc := root.ToBOCWithFlags(flags...)
		got, err := Sign(request(boc), key)
		if err != nil || got.SignatureHex != baseline.SignatureHex {
			t.Fatalf("ordinary indexed/CRC BOC: %v", err)
		}
	}
	plain := root.ToBOCWithFlags(false)
	mutated := func(at int, val byte) []byte { b := bytes.Clone(plain); b[at] = val; return b }
	cases := map[string][]byte{
		"trailing":             append(bytes.Clone(plain), 0),
		"multiple roots":       cell.ToBOCWithFlags([]*cell.Cell{root, leaf}, false),
		"zero roots":           mutated(7, 0),
		"root out of bounds":   mutated(10, 255),
		"zero count width":     mutated(4, 0),
		"bad count width":      mutated(4, 7),
		"bad offset width":     mutated(5, 9),
		"reserved flags":       mutated(4, 0x19),
		"truncated":            plain[:len(plain)-1],
		"root allocation bomb": {0xb5, 0xee, 0x9c, 0x72, 4, 1, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0},
		"unreachable cell":     {0xb5, 0xee, 0x9c, 0x72, 1, 1, 2, 1, 0, 4, 0, 0, 0, 0, 0},
		"invalid topup bit":    {0xb5, 0xee, 0x9c, 0x72, 1, 1, 1, 1, 0, 3, 0, 0, 1, 0},
		"exotic cell":          {0xb5, 0xee, 0x9c, 0x72, 1, 1, 1, 1, 0, 3, 0, 8, 2, 1},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if sig, err := Sign(request(b), key); err == nil || sig.SignatureHex != "" {
				t.Fatal("accepted malformed or ambiguous BOC")
			}
		})
	}
}

func TestBatchAggregateBound(t *testing.T) {
	r := Request{Version: 1, Family: TRON, PayloadType: TRONRawData, PayloadHex: strings.Repeat("00", MaxPayloadBytes)}
	requests := make([]Request, MaxBatchPayloadBytes/MaxPayloadBytes+1)
	for i := range requests {
		requests[i] = r
	}
	key := make([]byte, 32)
	key[31] = 1
	if sig, err := SignBatch(requests, key); err == nil || sig != nil {
		t.Fatal("oversize aggregate batch accepted")
	}
}

func TestCanonicalEVMChainID(t *testing.T) {
	var req Request
	for _, v := range vectors(t) {
		if v.Request.Family == EVM {
			req = v.Request
			break
		}
	}
	for _, chain := range []string{"01", strings.Repeat("1", 100000)} {
		req.ChainID = chain
		if err := ValidateRequest(req); err == nil {
			t.Fatal("noncanonical or oversized chain ID accepted")
		}
	}
}

func TestPrivateKeyBuffersAreNotTrimmedOrDisclosed(t *testing.T) {
	r := Request{Version: 1, Family: TRON, PayloadType: Digest, PayloadHex: strings.Repeat("42", 32)}
	key := bytes.Repeat([]byte{0x20}, 32)
	before := bytes.Clone(key)
	if _, err := Sign(r, key); err != nil {
		t.Fatalf("binary whitespace key was modified or rejected: %v", err)
	}
	if !bytes.Equal(key, before) {
		t.Fatal("caller key was mutated")
	}
	bad := bytes.Repeat([]byte{0x42}, 31)
	_, err := Sign(r, bad)
	if err == nil || strings.Contains(err.Error(), hex.EncodeToString(bad[:8])) || strings.Contains(err.Error(), string(bad[:8])) {
		t.Fatal("private material disclosed in error or invalid key accepted")
	}
}

func FuzzTONSigningBOC(f *testing.F) {
	root := cell.BeginCell().MustStoreUInt(42, 6).MustStoreRef(cell.BeginCell().EndCell()).EndCell()
	f.Add(root.ToBOCWithFlags(false))
	f.Add(root.ToBOCWithFlags(true, true))
	f.Add([]byte{0xb5, 0xee, 0x9c, 0x72, 1, 1, 1, 0, 0, 2, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxPayloadBytes {
			return
		}
		_, _ = tonCellDigest(b)
	})
}
