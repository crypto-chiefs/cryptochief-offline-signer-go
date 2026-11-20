package signer

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func processingCallback(family Family, address, tx string) []byte {
	return []byte(fmt.Sprintf(`{"chain_family":%q,"address":%q,"tx":%s}`, family, address, tx))
}

func TestProcessingEVMTransaction(t *testing.T) {
	const to = "0x3535353535353535353535353535353535353535"
	for _, tc := range []struct{ name, feeFields, payload, fee string }{
		{"legacy", `"gas_price":"0x2"`, "df800282520894" + to[2:] + "0180808080", "42000"},
		{"type 2", `"max_fee_per_gas":"0x3","max_priority_fee_per_gas":"0x1"`, "02e20180010382520894" + to[2:] + "0180c0808080", "63000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address := strings.ToLower(paymentEVMWallet.Address)
			tx := fmt.Sprintf(`{"chain_id":"0x1","nonce":"0x0","from":%q,"to":%q,"value":"0x1","data":"0x","gas":"0x5208",%s}`, address, to, tc.feeFields)
			got, err := DecodeSigningRequest(processingCallback(EVM, address, tx))
			if err != nil {
				t.Fatal(err)
			}
			want := Request{Version: 1, Family: EVM, PayloadType: EVMTransaction, ChainID: "1", PayloadHex: tc.payload}
			if got.Request != want || got.Address != address {
				t.Fatalf("decoded %+v, want %+v", got, want)
			}
			review, err := got.Inspect(paymentEVMWallet)
			if err != nil || len(review.Transfers) != 1 {
				t.Fatalf("inspection %+v, %v", review, err)
			}
			tr := review.Transfers[0]
			if tr.From != paymentEVMWallet.Address || tr.To != to || tr.Asset.Kind != "native" || tr.AmountAtomic != "1" || tr.FeeLimitAtomic != tc.fee {
				t.Fatalf("wrong transfer %+v", tr)
			}
			got.Address = to
			if _, err := got.Inspect(paymentEVMWallet); !errors.Is(err, ErrSender) {
				t.Fatalf("other callback address: %v", err)
			}
		})
	}
}

func TestProcessingTransactionEncodings(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	tests := []struct {
		family Family
		tx     string
		kind   PayloadType
		hex    string
	}{
		{Solana, `{"message_base64":"AP9B"}`, SolanaMessage, "00ff41"},
		{TRON, `{"raw_data_hex":"00ff41"}`, TRONRawData, "00ff41"},
		{TRON, `{"digest_hex":"` + digest + `"}`, Digest, digest},
		{TON, `{"payload_base64":"te6ccgEBAQEAAgAAAA=="}`, TONCell, "b5ee9c72010101010002000000"},
		{TON, `{"digest_hex":"` + digest + `"}`, Digest, digest},
		{XRP, `{"tx_blob_hex":"00ff41"}`, XRPBlob, "00ff41"},
		{XRPTestnet, `{"tx_blob_hex":"00ff41"}`, XRPBlob, "00ff41"},
		{XRP, `{"digest_hex":"` + digest + `"}`, Digest, digest},
	}
	for _, tc := range tests {
		got, err := DecodeSigningRequest(processingCallback(tc.family, "fixture-address", tc.tx))
		if err != nil || got.Request.PayloadType != tc.kind || got.Request.PayloadHex != tc.hex || got.Request.Family != tc.family {
			t.Errorf("%s/%s: %+v, %v", tc.family, tc.kind, got, err)
		}
	}
	for _, f := range []Family{BTC, BTCTestnet, LTC, LTCTestnet, BCH, BCHTestnet, DOGE, DOGETestnet} {
		var hashType uint32 = 1
		if f == BCH || f == BCHTestnet {
			hashType = 65
		}
		tx := fmt.Sprintf(`{"sighash_hex":%q,"hash_type":%d}`, digest, hashType)
		got, err := DecodeSigningRequest(processingCallback(f, "fixture-address", tx))
		if err != nil || got.Request != (Request{Version: 1, Family: f, PayloadType: Digest, PayloadHex: digest, HashType: hashType}) {
			t.Errorf("%s: %+v, %v", f, got, err)
		}
	}
}

func TestProcessingDigestContext(t *testing.T) {
	wallet := utxoTestWallet(t, BTC, 1)
	check := func(w Wallet, tx string, ctx InspectionContext, amount string, count int) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"address": w.Address, "chain_family": w.Family, "tx": json.RawMessage(tx), "inspection_context": ctx})
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeSigningRequest(body)
		if err != nil || !reflect.DeepEqual(got.InspectionContext, ctx) {
			t.Fatalf("%s: %+v, %v", w.Family, got, err)
		}
		info, err := got.Inspect(w)
		if err != nil || len(info.Transfers) != count || info.Transfers[0].AmountAtomic != amount {
			t.Fatalf("%s: %+v, %v", w.Family, info, err)
		}
		got.InspectionContext = InspectionContext{}
		if _, err = got.Inspect(w); !errors.Is(err, ErrContext) {
			t.Fatalf("unverifiable digest: %v", err)
		}
	}
	index := uint32(0)
	check(wallet, `{"sighash_hex":"`+btcHash0+`","hash_type":1}`, InspectionContext{PayloadHex: utxoSpendW, InputIndex: &index, PreviousTransactions: []string{utxoFundW}}, "50000", 2)
	check(paymentTONWallet, `{"digest_hex":"`+tonJettonHash+`"}`, InspectionContext{PayloadHex: tonJettonFixture}, "66051", 1)
}

func TestProcessingRequestRejectsAmbiguousOrInvalidInput(t *testing.T) {
	const digest = "1122334455667788990011223344556677889900112233445566778899001122"
	const evm = `{"chain_id":"0x1","nonce":"0","to":"0x3535353535353535353535353535353535353535","gas":"21000","data":"0x","value":"1","gas_price":"2"}`
	btc := string(processingCallback(BTC, "fixture-address", `{"hash_type":1,"sighash_hex":"`+digest+`"}`))
	withContext := func(ctx string) []byte {
		return []byte(strings.TrimSuffix(btc, "}") + `,"inspection_context":` + ctx + "}")
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want error
	}{
		{"unhandled family", processingCallback(Family("ETHEREUM"), "address", evm), ErrUnsupported},
		{"envelope", []byte(`{"event":"wallet.signature.requested","request":` + btc + `}`), ErrMalformed},
		{"duplicate escaped field", []byte(strings.Replace(btc, `"tx":`, `"\u0074x":{},"tx":`, 1)), ErrMalformed},
		{"case alias", []byte(strings.Replace(btc, `"tx":`, `"TX":`, 1)), ErrMalformed},
		{"null address", []byte(strings.Replace(btc, `"fixture-address"`, `null`, 1)), ErrMalformed},
		{"blank address", processingCallback(TRON, " ", `{"raw_data_hex":"ff"}`), ErrMalformed},
		{"extra JSON", []byte(btc + "{}"), ErrMalformed},
		{"two payloads", processingCallback(TRON, "address", `{"raw_data_hex":"ff","digest_hex":"`+digest+`"}`), ErrMalformed},
		{"invalid hash type", processingCallback(BCH, "address", `{"hash_type":1,"sighash_hex":"`+digest+`"}`), ErrMalformed},
		{"digest in place of Solana message", processingCallback(Solana, "address", `{"digest_hex":"`+digest+`"}`), ErrUnsupported},
		{"noncanonical base64", processingCallback(Solana, "address", `{"message_base64":"AB=="}`), ErrMalformed},
		{"EVM sender mismatch", processingCallback(EVM, paymentEVMWallet.Address, strings.Replace(evm, `"to":`, `"from":"0x3535353535353535353535353535353535353535","to":`, 1)), ErrSender},
		{"mixed fees", processingCallback(EVM, paymentEVMWallet.Address, strings.Replace(evm, `"gas_price":`, `"max_fee_per_gas":"1","gas_price":`, 1)), ErrMalformed},
		{"nonce overflow", processingCallback(EVM, paymentEVMWallet.Address, strings.Replace(evm, `"nonce":"0"`, `"nonce":"18446744073709551616"`, 1)), ErrMalformed},
		{"untrusted mint", withContext(`{"token_mint":"untrusted"}`), ErrMalformed},
		{"untrusted recipient", withContext(`{"recipient_owner":"untrusted"}`), ErrMalformed},
		{"bad source", withContext(`{"source_payload_hex":"a"}`), ErrContext},
		{"null parent", withContext(`{"previous_transactions":[null]}`), ErrContext},
		{"empty parents", withContext(`{"previous_transactions":[]}`), ErrContext},
		{"negative index", withContext(`{"input_index":-1}`), ErrContext},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeSigningRequest(tc.raw)
			if !errors.Is(err, tc.want) || !reflect.DeepEqual(got, SigningRequest{}) {
				t.Fatalf("decoded %+v, %v; want %v", got, err, tc.want)
			}
		})
	}
}
