package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Generated with wire.MsgTx, txscript.CalcSignatureHash and CalcWitnessSigHash
// from btcd v0.25.0, as used by the CryptoChief transaction service. Both
// inputs spend different outputs of the same funding transaction.
const (
	utxoKeyHash   = "751e76e8199196d454941c45d1b3a323f1433bd6"
	utxoPayeeHash = "06afd46bcdfd22ef94ac122aa11f241244a37ecc"
	utxoCoinbase  = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff03020101ffffffff02"
	utxoFundW     = utxoCoinbase + "50c3000000000000160014" + utxoKeyHash + "3075000000000000160014" + utxoKeyHash + "00000000"
	utxoFundP     = utxoCoinbase + "50c30000000000001976a914" + utxoKeyHash + "88ac30750000000000001976a914" + utxoKeyHash + "88ac00000000"
	utxoPrevW     = "c4c914b08489023cda7eaf31f2c091618efad8cff07626fd9c3cac70787f058d"
	utxoPrevP     = "6d92a84272c024c103f2b75b3237e63cf5df0a4390b1e11ef00e4dae17d6fa55"
	utxoSpendW    = "0200000002" + utxoPrevW + "0000000000fdffffff" + utxoPrevW + "0100000000fdffffff02" +
		"50c3000000000000160014" + utxoPayeeHash + "7869000000000000160014" + utxoKeyHash + "e4010000"
	utxoSpendP = "0200000002" + utxoPrevP + "0000000000fdffffff" + utxoPrevP + "0100000000fdffffff02" +
		"50c30000000000001976a914" + utxoPayeeHash + "88ac78690000000000001976a914" + utxoKeyHash + "88ace4010000"
	btcHash0 = "fc4a76a04071540b2dbb1a3efa4d7413d365b6cacc6afd6810861569148b0ab1"
	btcHash1 = "4a86bda41315d7a89d29bc1191479617a53c7861f250c9d27a6ebc475e9a329b"
)

func utxoTestWallet(t *testing.T, family Family, scalar byte) Wallet {
	t.Helper()
	key := make([]byte, 32)
	key[31] = scalar
	wallet, err := DeriveWallet(WalletOptions{Family: family}, key)
	if err != nil {
		t.Fatal(err)
	}
	return wallet
}

func TestInspectUTXOFamiliesAndAllOutputs(t *testing.T) {
	for _, tc := range []struct {
		families       []Family
		funding, spend string
		hashes         [2]string
		typ            uint32
	}{
		{[]Family{BTC, BTCTestnet, LTC, LTCTestnet}, utxoFundW, utxoSpendW, [2]string{btcHash0, btcHash1}, 1},
		{[]Family{BCH, BCHTestnet}, utxoFundP, utxoSpendP, [2]string{"93c7f66e5a392fb58b50aadaca2ac3bb23d977c945902022b04f46a164b2a9ad", "172d14f10e797380d85413dc1708be5855f303b6318a407d1c3e703fcc7addf0"}, 0x41},
		{[]Family{DOGE, DOGETestnet}, utxoFundP, utxoSpendP, [2]string{"7888ffb40afd241c63de4106f3b1d9ff51e2f878b8f0bd7b578fdee131b35536", "5bd125b4f75526fadfe9d67239842a8064106f6e5c9e72c7257ce0caa4c0c4dd"}, 1},
	} {
		for _, family := range tc.families {
			t.Run(string(family), func(t *testing.T) {
				owner := utxoTestWallet(t, family, 1)
				payee := utxoTestWallet(t, family, 2)
				for i, hash := range tc.hashes {
					index := uint32(i)
					req := Request{Version: 1, Family: family, PayloadType: Digest, HashType: tc.typ, PayloadHex: hash}
					ctx := InspectionContext{InputIndex: &index, PayloadHex: tc.spend, PreviousTransactions: []string{tc.funding}}
					got, err := InspectTransfer(req, owner, ctx)
					if err != nil || len(got.Transfers) != 2 || got.FeeAtomic != "3000" {
						t.Fatalf("input %d: %+v, %v", i, got, err)
					}
					if got.Transfers[0].To != payee.Address || got.Transfers[0].AmountAtomic != "50000" ||
						got.Transfers[1].To != owner.Address || got.Transfers[1].AmountAtomic != "27000" {
						t.Fatalf("outputs %+v", got.Transfers)
					}
					for _, move := range got.Transfers {
						if move.From != owner.Address || move.Asset != (Asset{Kind: "native"}) || move.FeeAtomic != "" {
							t.Fatalf("transfer %+v", move)
						}
					}
				}
			})
		}
	}
}

// Addresses were encoded independently with btcutil v1.1.6 and the transaction
// service's BCH EncodeCashAddr. Testnet Litecoin uses that service's P2SH prefix.
func TestUTXOStandardOutputAddresses(t *testing.T) {
	scripts := []string{"76a914" + utxoKeyHash + "88ac", "a914" + utxoKeyHash + "87", "0014" + utxoKeyHash, "0020" + strings.Repeat("23", 32), "5120" + strings.Repeat("23", 32)}
	for _, tc := range []struct {
		family    Family
		addresses []string
	}{
		{BTC, []string{"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "3CNHUhP3uyB9EUtRLsmvFUmvGdjGdkTxJw", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bc1qyv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3sxytjw8", "bc1pyv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3svntmkm"}},
		{BTCTestnet, []string{"mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", "2N3vVYSK5XRgVSGWy21PnsRmBUywSQNdCsf", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "tb1qyv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3s3vaa5g", "tb1pyv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3smma5v5"}},
		{LTC, []string{"LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ", "MJaRnao1s62a2zAKSkmG582KbLKianqb7v", "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9", "ltc1qyv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3s9q9z5z", "ltc1pyv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3s0h9tv7"}},
		{LTCTestnet, []string{"mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", "2N3vVYSK5XRgVSGWy21PnsRmBUywSQNdCsf", "tltc1qw508d6qejxtdg4y5r3zarvary0c5xw7klfsuq0", "tltc1qyv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3sw0puth", "tltc1pyv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3jxgeryv3sycp4nt"}},
		{DOGE, []string{"DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE", "A37YDYSwz3438rFtm1SLVcQHyD7JeueC9H"}},
		{DOGETestnet, []string{"nesRpRaAbTDmZHwmzBkLd2AtF7Z9L9z5S2", "2N3vVYSK5XRgVSGWy21PnsRmBUywSQNdCsf"}},
		{BCH, []string{"bitcoincash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h", "bitcoincash:pp63uahgrxged4z5jswyt5dn5v3lzsem6cnsdw2m32"}},
		{BCHTestnet, []string{"bchtest:qp63uahgrxged4z5jswyt5dn5v3lzsem6cq85x00dt", "bchtest:pp63uahgrxged4z5jswyt5dn5v3lzsem6chzffgvkk"}},
	} {
		net, err := inspectionUTXONetwork(tc.family)
		if err != nil {
			t.Fatal(err)
		}
		for i, wire := range scripts {
			script, _ := hex.DecodeString(wire)
			address, err := net.outputAddress(script)
			if i >= len(tc.addresses) {
				if !errors.Is(err, ErrUnsupported) {
					t.Errorf("%s: witness output resolved to %q, %v", tc.family, address, err)
				}
				continue
			}
			if err != nil || address != tc.addresses[i] {
				t.Errorf("%s %s: %q, %v; want %q", tc.family, wire, address, err, tc.addresses[i])
			}
		}
	}
}

func TestUTXOFundingTransactionUsesTxidWithoutWitness(t *testing.T) {
	funding := "020000000001" + utxoFundW[8:len(utxoFundW)-8] + "0120" + strings.Repeat("ab", 32) + "00000000"
	index := uint32(0)
	got, err := InspectTransfer(Request{Version: 1, Family: BTC, PayloadType: Digest, PayloadHex: btcHash0, HashType: 1},
		utxoTestWallet(t, BTC, 1), InspectionContext{InputIndex: &index, PayloadHex: utxoSpendW, PreviousTransactions: []string{funding}})
	if err != nil || len(got.Transfers) != 2 {
		t.Fatalf("segwit funding transaction: %+v, %v", got, err)
	}
}

func TestInspectUTXORejectsUnverifiedTransfers(t *testing.T) {
	index, badIndex := uint32(0), uint32(2)
	owner := utxoTestWallet(t, BTC, 1)
	mixed := strings.Replace(utxoFundW, utxoKeyHash, utxoPayeeHash, 1)
	raw, _ := hex.DecodeString(mixed)
	once := sha256.Sum256(raw)
	id := sha256.Sum256(once[:])
	mixedSpend := strings.ReplaceAll(utxoSpendW, utxoPrevW, hex.EncodeToString(id[:]))
	unknown := strings.Replace(utxoSpendW, "160014"+utxoKeyHash+"e4010000", "036a0131e4010000", 1)
	for _, tc := range []struct {
		name, spend, digest string
		funding             []string
		index               *uint32
		want                error
	}{
		{"missing index", utxoSpendW, btcHash0, []string{utxoFundW}, nil, ErrContext},
		{"wrong index", utxoSpendW, btcHash1, []string{utxoFundW}, &index, ErrMismatch},
		{"index outside transaction", utxoSpendW, btcHash0, []string{utxoFundW}, &badIndex, ErrContext},
		{"missing funding", utxoSpendW, btcHash0, nil, &index, ErrContext},
		{"changed funding txid", utxoSpendW, btcHash0, []string{mixed}, &index, ErrMismatch},
		{"funding with foreign owner", mixedSpend, btcHash0, []string{mixed}, &index, ErrSender},
		{"extra funding", utxoSpendW, btcHash0, []string{utxoFundW, utxoFundW}, &index, ErrContext},
		{"changed payment", strings.Replace(utxoSpendW, utxoPayeeHash, utxoKeyHash, 1), btcHash0, []string{utxoFundW}, &index, ErrMismatch},
		{"extra unsigned bytes", utxoSpendW + "00", btcHash0, []string{utxoFundW}, &index, ErrMalformed},
		{"noncanonical count", strings.Replace(utxoSpendW, "0200000002", "02000000fd0200", 1), btcHash0, []string{utxoFundW}, &index, ErrMalformed},
		{"duplicate outpoint", strings.Replace(utxoSpendW, utxoPrevW+"01000000", utxoPrevW+"00000000", 1), btcHash0, []string{utxoFundW}, &index, ErrMalformed},
		{"valid digest for unknown output", unknown, "efe877bf4673be5a921140efa7a0ca7d87a855a801af95e746a1b3ad616d8639", []string{utxoFundW}, &index, ErrUnsupported},
		{"valid digest spends too much", strings.Replace(utxoSpendW, "7869000000000000", "1879000000000000", 1), "00051cc2b9f4ef2ca4aa364919b087b165cf228b0956cb0cfe00137ffbafaa6c", []string{utxoFundW}, &index, ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := Request{Version: 1, Family: BTC, PayloadType: Digest, PayloadHex: tc.digest, HashType: 1}
			got, err := InspectTransfer(req, owner, InspectionContext{InputIndex: tc.index, PayloadHex: tc.spend, PreviousTransactions: tc.funding})
			if !errors.Is(err, tc.want) || len(got.Transfers) != 0 {
				t.Fatalf("got %+v, %v; want %v", got, err, tc.want)
			}
		})
	}
	req := Request{Version: 1, Family: BTC, PayloadType: Digest, PayloadHex: btcHash0, HashType: 1}
	ctx := InspectionContext{InputIndex: &index, PayloadHex: utxoSpendW, PreviousTransactions: []string{utxoFundW}}
	owner.PublicKeyHex = utxoTestWallet(t, BTC, 2).PublicKeyHex
	if _, err := InspectTransfer(req, owner, ctx); !errors.Is(err, ErrSender) {
		t.Errorf("unbound wallet key: %v", err)
	}
	owner = utxoTestWallet(t, BTCTestnet, 1)
	if _, err := InspectTransfer(req, owner, ctx); !errors.Is(err, ErrSender) {
		t.Errorf("wallet from another network: %v", err)
	}
}
