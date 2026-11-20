package signer_test

import (
	"fmt"

	signer "github.com/crypto-chiefs/cryptochief-offline-signer-go/v2"
)

// Public wallet record selected by the merchant before inspecting the request.
var exampleWallet = signer.Wallet{
	Family:       signer.EVM,
	Address:      "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
	PublicKeyHex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
}

func ExampleDecodeSigningRequest() {
	// The request field of an authenticated wallet.signature.requested event.
	raw := []byte(`{
		"chain_family":"EVM", "address":"0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
		"tx":{
			"chain_id":"0x1", "nonce":"0x7", "gas":"0xfde8",
			"max_fee_per_gas":"0x14", "max_priority_fee_per_gas":"0x2", "value":"0x0",
			"to":"0x2222222222222222222222222222222222222222",
			"data":"0xa9059cbb000000000000000000000000111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000000f4240"
		}
	}`)
	prepared, err := signer.DecodeSigningRequest(raw)
	if err != nil {
		panic(err)
	}
	review, err := prepared.Inspect(exampleWallet)
	if err != nil {
		panic(err)
	}
	for _, transfer := range review.Transfers {
		fmt.Println(transfer.From, transfer.To)
		fmt.Println(transfer.AmountAtomic, transfer.Asset.Kind, transfer.Asset.Contract)
	}
	// Output:
	// 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf 0x1111111111111111111111111111111111111111
	// 1000000 token 0x2222222222222222222222222222222222222222
}

func ExampleInspectTransfer() {
	req := signer.Request{
		Version: 1, Family: signer.EVM, ChainID: "1", PayloadType: signer.EVMTransaction,
		PayloadHex: "e107148252089411111111111111111111111111111111111111118203e880808080",
	}
	review, err := signer.InspectTransfer(req, exampleWallet, signer.InspectionContext{})
	if err != nil {
		panic(err)
	}
	for _, transfer := range review.Transfers {
		fmt.Println(transfer.To, transfer.AmountAtomic, transfer.Asset.Kind)
	}
	// Output: 0x1111111111111111111111111111111111111111 1000 native
}

func ExampleGenerateWallet() {
	options := signer.WalletOptions{Family: signer.BTC}
	wallet, privateKey, err := signer.GenerateWallet(options)
	if err != nil {
		panic("wallet generation failed")
	}
	defer clear(privateKey)

	// The key process stores privateKey; only wallet is a public API record.
	// After decrypting a stored key, reconstruct and compare its public details.
	restored, err := signer.DeriveWallet(options, privateKey)
	if err != nil {
		panic("wallet derivation failed")
	}
	matched := restored.Address == wallet.Address &&
		restored.PublicKeyHex == wallet.PublicKeyHex
	fmt.Println(wallet.Family, matched)
	// Output: BTC_UTXO true
}

func ExampleSign() {
	// Demo-only key and synthetic prepared sighash. Never use this key for funds.
	// In production, Crypto Chief supplies the payload, the external verifier
	// approves the complete request, and the key process supplies the matching key.
	privateKey := make([]byte, 32)
	privateKey[31] = 1
	defer clear(privateKey)

	raw := []byte(`{
  "version": 1,
  "chain_family": "BTC_UTXO",
  "payload_type": "digest",
  "payload_hex": "4200000000000000000000000000000000000000000000000000000000000000",
  "hash_type": 1
}`)
	signature, err := signPrepared(raw, privateKey)
	if err != nil {
		panic("signing failed")
	}
	// Return the signature to the authorized caller; do not log signed material.
	fmt.Println(signature.Algorithm)
	// Output: secp256k1-der
}

// signPrepared requires prior external authorization of the complete request
// and its binding to privateKey. Decoding alone does not authorize signing.
func signPrepared(raw, privateKey []byte) (signer.Signature, error) {
	request, err := signer.DecodeRequest(raw)
	if err != nil {
		return signer.Signature{}, err
	}
	return signer.Sign(request, privateKey)
}

func ExampleSignTRONMessage() {
	_, privateKey, err := signer.GenerateWallet(signer.WalletOptions{Family: signer.TRON})
	if err != nil {
		panic("wallet generation failed")
	}
	defer clear(privateKey)

	// Message signing needs separate approval covering both the exact message
	// and prefix mode. This example uses a demonstration message only.
	signature, err := signer.SignTRONMessage(
		"Crypto Chief offline signing demo",
		signer.TRONPrefixV2,
		privateKey,
	)
	if err != nil {
		panic("message signing failed")
	}
	fmt.Println(signature.Family, signature.Algorithm)
	// Output: TRON secp256k1-rsv
}
