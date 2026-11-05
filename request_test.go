package signer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestStrictRequestDecode(t *testing.T) {
	r := vectors(t)[0].Request
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := DecodeRequest(raw)
	if err != nil || parsed != r {
		t.Fatalf("roundtrip: %v", err)
	}
	base := string(raw)
	cases := []string{
		`null`, `[]`, `{}`, base + `{}`, base + `junk`,
		strings.Replace(base, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(base, `"version":1`, `"version":1,"\u0076ersion":1`, 1),
		strings.Replace(base, `"version":1`, `"Version":1`, 1),
		strings.Replace(base, `"version":1`, `"version":1.0`, 1),
		strings.Replace(base, `"version":1`, `"version":null`, 1),
		strings.Replace(base, `"version":1,`, ``, 1),
		strings.Replace(base, `"version":1`, `"version":1,"private_key":"never accepted"`, 1),
		strings.Replace(base, `"hash_type":1`, `"hash_type":null`, 1),
		strings.Replace(base, `"hash_type":1`, `"hash_type":4294967297`, 1),
		strings.Replace(base, `"hash_type":1`, `"hash_type":"1"`, 1),
	}
	for _, s := range cases {
		if _, err := DecodeRequest([]byte(s)); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	if _, err := DecodeRequest(bytes.Repeat([]byte{' '}, MaxRequestJSONBytes+1)); err == nil {
		t.Fatal("oversize accepted")
	}
}

func TestCanonicalRequestBinding(t *testing.T) {
	r := vectors(t)[0].Request
	want := `{"version":1,"chain_family":"BTC_UTXO","payload_type":"digest","payload_hex":"4200000000000000000000000000000000000000000000000000000000000000","hash_type":1}`
	b, e := CanonicalRequest(r)
	if e != nil || string(b) != want {
		t.Fatalf("canonical format: %s %v", b, e)
	}
	d, e := RequestDigest(r)
	if e != nil {
		t.Fatal(e)
	}
	for _, edit := range []func(*Request){
		func(r *Request) { r.Family = BTCTestnet },
		func(r *Request) { r.Family = BCH; r.HashType = 65 },
		func(r *Request) { r.PayloadHex = "43" + r.PayloadHex[2:] },
	} {
		changed := r
		edit(&changed)
		other, e := RequestDigest(changed)
		if e != nil || other == d {
			t.Fatalf("unbound request: %v", e)
		}
	}
	for _, v := range vectors(t) {
		if v.Name != "evm-legacy" {
			continue
		}
		a, _ := RequestDigest(v.Request)
		v.Request.ChainID = "2"
		b, e := RequestDigest(v.Request)
		if e != nil || a == b {
			t.Fatal("chain id not bound")
		}
	}
	// Wire whitespace/order don't affect the canonical payload digest.
	parsed, e := DecodeRequest([]byte(" \n" + want + "\n"))
	if e != nil {
		t.Fatal(e)
	}
	same, _ := RequestDigest(parsed)
	if same != d {
		t.Fatal("unstable canonical hash")
	}
}

func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := DecodeRequest(raw)
		if err != nil {
			return
		}
		canonical, err := CanonicalRequest(r)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeRequest(canonical)
		if err != nil || r != again {
			t.Fatal("roundtrip failed")
		}
	})
}
