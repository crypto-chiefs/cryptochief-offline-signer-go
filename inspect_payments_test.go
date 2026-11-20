package signer

import (
	"encoding/hex"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Public test wallets from testdata/wallet-service-vectors.json.
var paymentEVMWallet = Wallet{Family: EVM, Address: "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", PublicKeyHex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}
var paymentTRONWallet = Wallet{Family: TRON, Address: "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC", PublicKeyHex: paymentEVMWallet.PublicKeyHex}
var paymentTONWallet = Wallet{Family: TON, Address: "EQAkxuybaeBflbgYW3vgQvcFgyAQVcLtXZwdrpeLNqzZ000c", PublicKeyHex: "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29"}

func assertInspectedPayments(t *testing.T, req Request, wallet Wallet, ctx InspectionContext, payments ...Transfer) {
	t.Helper()
	view, err := InspectTransfer(req, wallet, ctx)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := RequestDigest(req)
	if err != nil {
		t.Fatal(err)
	}
	if view.ChainFamily != req.Family || view.ChainID != req.ChainID || view.PayloadDigest != digest {
		t.Errorf("preview did not preserve the SDK request identity: %+v", view)
	}
	if !reflect.DeepEqual(view.Transfers, payments) {
		t.Errorf("transfers = %+v, want %+v", view.Transfers, payments)
	}
}

func assertPaymentRefused(t *testing.T, req Request, wallet Wallet, ctx InspectionContext, want error) {
	t.Helper()
	view, err := InspectTransfer(req, wallet, ctx)
	if !errors.Is(err, want) || !reflect.DeepEqual(view, Inspection{}) {
		t.Errorf("expected %v and an empty inspection, got %+v, %v", want, view, err)
	}
}

func TestInspectEVMPayments(t *testing.T) {
	recipient := common.HexToAddress("0x1111111111111111111111111111111111111111")
	contract := common.HexToAddress("0x2222222222222222222222222222222222222222")
	data := make([]byte, 68)
	copy(data, []byte{0xa9, 0x05, 0x9c, 0xbb})
	copy(data[16:36], recipient.Bytes())
	amount := new(big.Int).Lsh(big.NewInt(1), 110)
	amount.FillBytes(data[36:])
	request := func(tx *types.Transaction, chain string) Request {
		raw, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return Request{Version: 1, Family: EVM, PayloadType: EVMTransaction, ChainID: chain, PayloadHex: hex.EncodeToString(raw)}
	}
	legacy := request(types.NewTx(&types.LegacyTx{Nonce: 1, To: &recipient, Value: amount, Gas: 21000, GasPrice: big.NewInt(7)}), "1")
	assertInspectedPayments(t, legacy, paymentEVMWallet, InspectionContext{}, Transfer{From: paymentEVMWallet.Address, To: recipient.Hex(), AmountAtomic: amount.String(), Asset: Asset{Kind: "native"}, FeeLimitAtomic: "147000"})
	token := func(call []byte, native int64) Request {
		return request(types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(137), Nonce: 4, To: &contract, Value: big.NewInt(native), Gas: 65000, GasTipCap: big.NewInt(2), GasFeeCap: big.NewInt(11), Data: call}), "137")
	}
	erc20 := token(data, 0)
	assertInspectedPayments(t, erc20, paymentEVMWallet, InspectionContext{}, Transfer{From: paymentEVMWallet.Address, To: recipient.Hex(), AmountAtomic: amount.String(), Asset: Asset{Kind: "token", Contract: contract.Hex()}, FeeLimitAtomic: "715000"})
	t.Run("unexpected source context", func(t *testing.T) {
		assertPaymentRefused(t, legacy, paymentEVMWallet, InspectionContext{PayloadHex: legacy.PayloadHex}, ErrContext)
	})
	t.Run("inconsistent public wallet record", func(t *testing.T) {
		other := paymentEVMWallet
		other.Address = recipient.Hex()
		assertPaymentRefused(t, legacy, other, InspectionContext{}, ErrSender)
	})
	t.Run("attached native value on token call", func(t *testing.T) {
		assertPaymentRefused(t, token(data, 1), paymentEVMWallet, InspectionContext{}, ErrUnsupported)
	})
	t.Run("unknown selector", func(t *testing.T) {
		call := append([]byte(nil), data...)
		copy(call, []byte{9, 0x5e, 0xa7, 0xb3})
		assertPaymentRefused(t, token(call, 0), paymentEVMWallet, InspectionContext{}, ErrUnsupported)
	})
	t.Run("trailing call data", func(t *testing.T) {
		assertPaymentRefused(t, token(append(data, 0), 0), paymentEVMWallet, InspectionContext{}, ErrUnsupported)
	})
	t.Run("wrong chain", func(t *testing.T) {
		wrong := erc20
		wrong.ChainID = "1"
		assertPaymentRefused(t, wrong, paymentEVMWallet, InspectionContext{}, ErrMalformed)
	})
}

// protocol.Transaction.raw, carrying TransferContract or TriggerSmartContract in
// a protobuf Any. These encode the node's raw_data_hex used by the TRON builder.
// The address words, fee limit and memo are set independently of the decoder.
const (
	tronNativeFixture = "0a0212342208010203040506070840e094acca9a3a52086f726465722d34325a67080112630a2d747970652e676f6f67" +
		"6c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15417e5f4552091a69" +
		"125d5dfcb7b8c2659029395bdf1215411111111111111111111111111111111111111111188384047080c0a8ca9a3a"
	tronTokenFixture = "0a0212342208010203040506070840e094acca9a3a52086f726465722d34325aae01081f12a9010a31747970652e676f" +
		"6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a15417e" +
		"5f4552091a69125d5dfcb7b8c2659029395bdf12154122222222222222222222222222222222222222222244a9059cbb" +
		"000000000000000000000000111111111111111111111111111111111111111100000000000000000000000000000000" +
		"000000000000000000000000000102037080c0a8ca9a3a90018087a70e"
	tronTokenHash     = "265760313b93daf712488e205e45eb4a9920610f8a7b6c3c38a83df3b04cf2ca"
	tronExtraContract = "5a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e" +
		"747261637412320a15417e5f4552091a69125d5dfcb7b8c2659029395bdf121541111111111111111111111111111111" +
		"111111111118838404"
)

func TestInspectTRONPayments(t *testing.T) {
	native := Request{Version: 1, Family: TRON, PayloadType: TRONRawData, PayloadHex: tronNativeFixture}
	token := Request{Version: 1, Family: TRON, PayloadType: TRONRawData, PayloadHex: tronTokenFixture}
	digest := Request{Version: 1, Family: TRON, PayloadType: Digest, PayloadHex: tronTokenHash}
	n := Transfer{From: paymentTRONWallet.Address, To: "TBXSw8fM4jpQkGc6zZjsVABFpVN7UvXPdV", AmountAtomic: "66051", Asset: Asset{Kind: "native"}, Memo: "order-42"}
	asset := Transfer{From: paymentTRONWallet.Address, To: "TBXSw8fM4jpQkGc6zZjsVABFpVN7UvXPdV", AmountAtomic: "66051", Asset: Asset{Kind: "token", Contract: "TD5gsCwxykWsLN9aPrq2TAfNjByuZKYp4E"}, Memo: "order-42", FeeLimitAtomic: "30000000"}
	assertInspectedPayments(t, native, paymentTRONWallet, InspectionContext{}, n)
	assertInspectedPayments(t, token, paymentTRONWallet, InspectionContext{}, asset)
	assertInspectedPayments(t, digest, paymentTRONWallet, InspectionContext{PayloadHex: tronTokenFixture}, asset)
	t.Run("missing raw data", func(t *testing.T) {
		assertPaymentRefused(t, digest, paymentTRONWallet, InspectionContext{}, ErrContext)
	})
	t.Run("other raw data", func(t *testing.T) {
		assertPaymentRefused(t, digest, paymentTRONWallet, InspectionContext{PayloadHex: tronNativeFixture}, ErrMismatch)
	})
	t.Run("another owner", func(t *testing.T) {
		other := paymentTRONWallet
		other.Address = n.To
		assertPaymentRefused(t, native, other, InspectionContext{}, ErrSender)
	})
	t.Run("public key differs from signing wallet", func(t *testing.T) {
		other := paymentTRONWallet
		other.PublicKeyHex = "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
		assertPaymentRefused(t, native, other, InspectionContext{}, ErrSender)
	})
	t.Run("two contracts", func(t *testing.T) {
		extra := native
		extra.PayloadHex += tronExtraContract
		assertPaymentRefused(t, extra, paymentTRONWallet, InspectionContext{}, ErrUnsupported)
	})
	t.Run("different smart-contract method", func(t *testing.T) {
		unknown := token
		unknown.PayloadHex = strings.Replace(unknown.PayloadHex, "a9059cbb", "095ea7b3", 1)
		assertPaymentRefused(t, unknown, paymentTRONWallet, InspectionContext{}, ErrUnsupported)
	})
}

// TON V4R2 signing cells, encoded with tonutils-go tlb.ToCell using the
// transaction builder's internal message and TEP-74 body layouts. Native
// delivery is non-bouncing. The jetton wallet gets 0.07 TON attached, and
// forwards one nanoton to notify the destination with the comment in a ref.
const (
	tonNativeFixture = "b5ee9c7241010201005300011c29a9a317773594000000000b0003010080420008888888888888888888888888888888" +
		"88888888888888888888888888888888a02160ec0000000000000000000000000000000000006f726465722d3432331b" +
		"844d"
	tonJettonFixture = "b5ee9c724101040100ad00011c29a9a317773594000000000b0003010168620011111111111111111111111111111111" +
		"11111111111111111111111111111111202160ec00000000000000000000000000010201a80f8a7ea500000000000000" +
		"0030102038002222222222222222222222222222222222222222222222222222222222222223000931bb26da7817e56e" +
		"0616def810bdc160c8041570bb5767076ba5e2cdab3674c203030018000000006f726465722d34320096de3a"
	tonJettonHash   = "ff74064b3bafe1b93165abdeeaa3b28a0648a6aca671c99e25e6c789395dd689"
	tonBatchFixture = "b5ee9c724101050100f100021e29a9a317773594000000000b0003030102008042000888888888888888888888888888" +
		"888888888888888888888888888888888888a02160ec0000000000000000000000000000000000006f726465722d3432" +
		"016862001111111111111111111111111111111111111111111111111111111111111111202160ec0000000000000000" +
		"0000000000010301a80f8a7ea50000000000000000301020380022222222222222222222222222222222222222222222" +
		"22222222222222222223000931bb26da7817e56e0616def810bdc160c8041570bb5767076ba5e2cdab3674c203040018" +
		"000000006f726465722d34326422bb3c"
	tonMixedOpsFixture = "b5ee9c7241010301008d00021e29a9a317773594000000000b0003030102008042000888888888888888888888888888" +
		"888888888888888888888888888888888888a02160ec0000000000000000000000000000000000006f726465722d3432" +
		"006c42000888888888888888888888888888888888888888888888888888888888888888901f40000000000000000000" +
		"0000000000bc614e102185ee"
	tonCarryFixture = "b5ee9c7241010201005300011c29a9a317773594000000000b0083010080420008888888888888888888888888888888" +
		"88888888888888888888888888888888a02160ec0000000000000000000000000000000000006f726465722d34321d87" +
		"1c72"
)

func TestInspectTONPayments(t *testing.T) {
	req := func(kind PayloadType, payload string) Request {
		return Request{Version: 1, Family: TON, PayloadType: kind, PayloadHex: payload}
	}
	native := Transfer{From: paymentTONWallet.Address, To: "UQAREREREREREREREREREREREREREREREREREREREREREbvW", AmountAtomic: "70000000", Asset: Asset{Kind: "native"}, Memo: "order-42"}
	token := Transfer{From: paymentTONWallet.Address, To: "EQAREREREREREREREREREREREREREREREREREREREREREeYT", AmountAtomic: "66051", Asset: Asset{Kind: "jetton_wallet", Contract: "EQAiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIp3C"}, AttachedNativeAtomic: "70000000", ForwardNativeAtomic: "1", Memo: "order-42"}
	assertInspectedPayments(t, req(TONCell, tonNativeFixture), paymentTONWallet, InspectionContext{}, native)
	assertInspectedPayments(t, req(TONCell, tonJettonFixture), paymentTONWallet, InspectionContext{}, token)
	assertInspectedPayments(t, req(TONCell, tonBatchFixture), paymentTONWallet, InspectionContext{}, native, token)
	digest := req(Digest, tonJettonHash)
	assertInspectedPayments(t, digest, paymentTONWallet, InspectionContext{PayloadHex: tonJettonFixture}, token)
	t.Run("mismatched signing cell", func(t *testing.T) {
		assertPaymentRefused(t, digest, paymentTONWallet, InspectionContext{PayloadHex: tonNativeFixture}, ErrMismatch)
	})
	t.Run("missing signing cell", func(t *testing.T) { assertPaymentRefused(t, digest, paymentTONWallet, InspectionContext{}, ErrContext) })
	t.Run("additional unknown operation", func(t *testing.T) {
		assertPaymentRefused(t, req(TONCell, tonMixedOpsFixture), paymentTONWallet, InspectionContext{}, ErrUnsupported)
	})
	t.Run("carry mode has no fixed amount", func(t *testing.T) {
		assertPaymentRefused(t, req(TONCell, tonCarryFixture), paymentTONWallet, InspectionContext{}, ErrUnsupported)
	})
}
