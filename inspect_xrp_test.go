package signer

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// Unsigned Payments from rubblelabs/ripple data.Raw, using the same TxBase,
// Amount, LastLedgerSequence and zero destination tag as the production builder.
const (
	testXRPWallet  = "rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH"
	testXRPPub     = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	testXRPDest    = "rHsqGHS8YE6sm16n4u3xKQfBB2r5GoAkd"
	testXRPIssuer  = "rjRcWSZh9Kyy2mHWy6Qarf5UaJSNTwqtw"
	testXRPNative  = "12000024000003db2e00000000201b000004d261400000000012d68768400000000000000c73210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817988114751e76e8199196d454941c45d1b3a323f1433bd683140309050000000000000000000000000000000000"
	testXRPIOU     = "12000024000003db2e00000000201b000004d261d48462d5077c86000000000000000000000000005553440000000000080604000000000000000000000000000000000068400000000000000c73210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817988114751e76e8199196d454941c45d1b3a323f1433bd683140309050000000000000000000000000000000000"
	testXRPPartial = "120000220002000024000003db2e00000000201b000004d261d48462d5077c86000000000000000000000000005553440000000000080604000000000000000000000000000000000068400000000000000c73210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817988114751e76e8199196d454941c45d1b3a323f1433bd683140309050000000000000000000000000000000000"
	testXRPSendMax = "12000024000003db2e00000000201b000004d261d48462d5077c86000000000000000000000000005553440000000000080604000000000000000000000000000000000068400000000000000c69400000000000006373210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817988114751e76e8199196d454941c45d1b3a323f1433bd683140309050000000000000000000000000000000000"
)

func TestXRPPaymentBuilderRoundTrip(t *testing.T) {
	for _, family := range []Family{XRP, XRPTestnet} {
		wallet := Wallet{Family: family, Address: testXRPWallet, PublicKeyHex: testXRPPub}
		for _, tc := range []struct {
			wire, atomic, decimal string
			asset                 Asset
		}{
			{testXRPNative, "1234567", "", Asset{Kind: "native"}},
			{testXRPIOU, "", "1.234567", Asset{Kind: "issued", Currency: "USD", Issuer: testXRPIssuer}},
		} {
			raw, _ := hex.DecodeString(tc.wire)
			ts, err := inspectXRP(Request{Family: family, PayloadType: XRPBlob}, raw, wallet, InspectionContext{})
			if err != nil || len(ts) != 1 {
				t.Fatalf("%s: %v %v", family, ts, err)
			}
			got := ts[0]
			if got.From != wallet.Address || got.To != testXRPDest || got.FeeAtomic != "12" || got.AmountAtomic != tc.atomic || got.AmountDecimal != tc.decimal || got.Asset != tc.asset || got.DestinationTag == nil || *got.DestinationTag != 0 {
				t.Fatalf("unexpected payment: %+v", got)
			}
		}
	}
}

func TestXRPRejectsPaymentsWithDifferentSemantics(t *testing.T) {
	wallet := Wallet{Family: XRP, Address: testXRPWallet, PublicKeyHex: testXRPPub}
	native, _ := hex.DecodeString(testXRPNative)
	partial, _ := hex.DecodeString(testXRPPartial)
	sendMax, _ := hex.DecodeString(testXRPSendMax)
	iou, _ := hex.DecodeString(testXRPIOU)
	anyIssuer := bytes.Replace(iou, []byte{8, 6, 4}, []byte{3, 9, 5}, 1)
	for _, tc := range []struct {
		name string
		raw  []byte
		want error
	}{
		{"partial payment", partial, ErrUnsupported}, {"SendMax", sendMax, ErrUnsupported},
		{"destination used as wildcard issuer", anyIssuer, ErrUnsupported},
		{"escrow transaction", append([]byte{0x12, 0, 1}, native[3:]...), ErrUnsupported},
		{"additional PathSet", append(bytes.Clone(native), 0x01, 0x12, 0), ErrUnsupported},
		{"duplicate transaction type", append([]byte{0x12, 0, 0}, native...), ErrMalformed},
		{"no destination", native[:len(native)-22], ErrMalformed},
		{"truncated destination", native[:len(native)-1], ErrMalformed},
		{"wrong account", bytes.Replace(native, []byte{0x81, 0x14, 0x75}, []byte{0x81, 0x14, 0x76}, 1), ErrSender},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := inspectXRP(Request{}, tc.raw, wallet, InspectionContext{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
	wallet.PublicKeyHex = "00"
	if _, err := inspectXRP(Request{}, native, wallet, InspectionContext{}); !errors.Is(err, ErrSender) {
		t.Fatalf("wrong key: %v", err)
	}
}
