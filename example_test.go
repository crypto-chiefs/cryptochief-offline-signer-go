package signer_test

import (
	"fmt"

	signer "github.com/crypto-chiefs/cryptochief-offline-signer-go"
)

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
