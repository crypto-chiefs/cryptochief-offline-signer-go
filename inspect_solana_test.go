package signer

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// Fixtures serialized by the same solana-go v1.14 instruction builders and
// Message.MarshalBinary that transaction-microservice uses for payments.
const (
	testSOLWallet   = "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF"
	testSOLPub      = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	testSOLOwner    = "GjkMYtxLQ4pHNHUEtiJcrRSzXYCernMVRr72nBzLp4o"
	testSOLMint     = "cEsVf43CsHmV9XZC9wUZ2arTwjZgtSMGgRd4seh8o91"
	testSOLSource   = "FV4SZUCQpLY9anjMHNxjkxde6Q2LMho1CDxzdXtTehxZ"
	testSOLDest     = "5o6zi1HWp4f64bZFix4ekqRSFKMRRRArpob2EbMAdwnT"
	testSOLNative   = "0100020403a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b804080c00000000000000000000000000000000000000000000000000000000000306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000000000000000000000000000000000000000000000000000000000000000000007040200000000000000000000000000000000000000000000000000000000000302000502400d0300020009036400000000000000030200010c0200000069b6010000000000"
	testSOLVersion0 = "800100010303a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b804080c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000070402000000000000000000000000000000000000000000000000000000000001020200010c0200000069b601000000000000"
	testSOLCreate   = "0100060903a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8473e3e51914424ce49d524682e893197d2e01cd843dc54ec503a0f0526135594d733c51fff847df2b50e2904f4b2e7e100279b60970ad74fa4cf837b78ac30fe04080c00000000000000000000000000000000000000000000000000000000000907030800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a400000008c97258f4e2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f85907040200000000000000000000000000000000000000000000000000000000000407000502400d03000700090364000000000000000806000103040506000603020100090369b6010000000000"
	testSOLPlain    = "0100010403a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8d733c51fff847df2b50e2904f4b2e7e100279b60970ad74fa4cf837b78ac30fe473e3e51914424ce49d524682e893197d2e01cd843dc54ec503a0f052613559406ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90704020000000000000000000000000000000000000000000000000000000000010303010200090369b6010000000000"
	testSOLChecked  = "0100020503a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8d733c51fff847df2b50e2904f4b2e7e100279b60970ad74fa4cf837b78ac30fe473e3e51914424ce49d524682e893197d2e01cd843dc54ec503a0f0526135594090703080000000000000000000000000000000000000000000000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90704020000000000000000000000000000000000000000000000000000000000010404010302000a0c69b601000000000006"
	testSOLExtra    = "0100020603a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8d733c51fff847df2b50e2904f4b2e7e100279b60970ad74fa4cf837b78ac30fe473e3e51914424ce49d524682e893197d2e01cd843dc54ec503a0f052613559404080c000000000000000000000000000000000000000000000000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a900000000000000000000000000000000000000000000000000000000000000000704020000000000000000000000000000000000000000000000000000000000020403010200090369b6010000000000050200030c020000007b00000000000000"
)

func TestSolanaInspectionOfTransactionBuilderMessages(t *testing.T) {
	wallet := Wallet{Family: Solana, Address: testSOLWallet, PublicKeyHex: testSOLPub}
	known := InspectionContext{RecipientOwner: testSOLOwner, TokenMint: testSOLMint}
	for _, tc := range []struct {
		name, wire            string
		ctx                   InspectionContext
		token, create, budget bool
		role                  string
	}{
		{"native mainnet", testSOLNative, InspectionContext{}, false, false, true, ""},
		{"v0 with static keys", testSOLVersion0, InspectionContext{}, false, false, false, ""},
		{"create ATA and plain transfer", testSOLCreate, InspectionContext{}, true, true, true, ""},
		{"verified ATA and mint", testSOLPlain, known, true, false, false, ""},
		{"mint without owner", testSOLPlain, InspectionContext{TokenMint: testSOLMint}, true, false, false, "token_account"},
		{"signed mint without owner", testSOLChecked, InspectionContext{}, true, false, false, "token_account"},
		{"signed mint with recipient", testSOLChecked, InspectionContext{RecipientOwner: testSOLOwner}, true, false, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			transfers, err := inspectSolana(Request{Family: Solana, PayloadType: SolanaMessage}, raw, wallet, tc.ctx)
			if err != nil || len(transfers) != 1 {
				t.Fatalf("transfers=%v err=%v", transfers, err)
			}
			got := transfers[0]
			to := testSOLOwner
			if tc.role == "token_account" {
				to = testSOLDest
			}
			if got.From != testSOLWallet || got.To != to || got.ToRole != tc.role || got.AmountAtomic != "112233" || got.CreatesDestinationAccount != tc.create {
				t.Errorf("transfer: %+v", got)
			}
			if tc.token && (got.Asset != (Asset{Kind: "token", Contract: testSOLMint}) || got.SourceAccount != testSOLSource || got.DestinationAccount != testSOLDest) {
				t.Errorf("SPL accounts: %+v", got)
			}
			if !tc.token && got.Asset != (Asset{Kind: "native"}) {
				t.Errorf("asset: %+v", got.Asset)
			}
			if tc.budget && (got.ComputeUnitLimit != 200000 || got.ComputeUnitPriceMicroLamports != "100") {
				t.Errorf("budget: %+v", got)
			}
		})
	}
}

func TestSolanaRefusesUnprovenTransfers(t *testing.T) {
	wallet := Wallet{Family: Solana, Address: testSOLWallet, PublicKeyHex: testSOLPub}
	var wrongOwner = InspectionContext{TokenMint: testSOLMint, RecipientOwner: testSOLWallet}
	for _, tc := range []struct {
		name, wire string
		ctx        InspectionContext
		want       error
	}{
		{"no mint in plain transfer", testSOLPlain, InspectionContext{}, ErrContext},
		{"source ATA disagrees with supplied mint", testSOLPlain, InspectionContext{TokenMint: testSOLOwner}, ErrSender},
		{"wrong destination ATA", testSOLPlain, wrongOwner, ErrContext},
		{"create names another owner", testSOLCreate, wrongOwner, ErrContext},
		{"transfer checked names another mint", testSOLChecked, InspectionContext{TokenMint: testSOLOwner}, ErrContext},
		{"extra movement", testSOLExtra, InspectionContext{TokenMint: testSOLMint}, ErrUnsupported},
		{"truncated amount", testSOLNative[:len(testSOLNative)-2], InspectionContext{}, ErrMalformed},
		{"trailing data", testSOLNative + "00", InspectionContext{}, ErrMalformed},
		{"unresolved address table", testSOLVersion0[:len(testSOLVersion0)-2] + "01", InspectionContext{}, ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := hex.DecodeString(tc.wire)
			_, err := inspectSolana(Request{}, raw, wallet, tc.ctx)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
	raw, _ := hex.DecodeString(testSOLNative)
	raw = bytes.Clone(raw)
	raw[4] ^= 1
	if _, err := inspectSolana(Request{}, raw, wallet, InspectionContext{}); !errors.Is(err, ErrSender) {
		t.Fatalf("wrong fee payer: %v", err)
	}
}
