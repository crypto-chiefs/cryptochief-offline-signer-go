// Package signer provides offline cryptocurrency wallet generation and transaction
// signing for Crypto Chief merchant integrations in Go.
//
// It supports EVM, Bitcoin, Litecoin, Bitcoin Cash, Dogecoin, TRON, TON, XRP Ledger
// and Solana, including the supported testnet family aliases. All operations run
// locally. The package makes no network requests and does not store or log keys.
//
// # Wallets
//
// GenerateWallet returns a public Wallet record and a separate 32-byte private
// key or Ed25519 seed. DeriveWallet reconstructs the address and public key from
// an existing secret so the caller can compare them with its wallet registry.
// WalletOptions selects the family and optional TON address flags.
//
// # Signing prepared payloads
//
// Crypto Chief prepares transactions and their signing payloads. Sign accepts a
// versioned Request and a raw private key, then returns a Signature with public
// verification data. SignBatch signs multiple prepared inputs with the same key.
// Transaction construction, fees, nonce and UTXO selection, signature attachment,
// broadcasting and confirmation tracking remain outside this package.
//
// PayloadType identifies the exact input format. Solana signs its compiled message
// bytes; TON signs a cell hash; UTXO families sign one prepared sighash per input.
// DecodeRequest validates SDK request JSON before Sign. SignTRONMessage supports
// TIP-191 messages with an explicit prefix mode.
//
// # Merchant integration
//
// The caller authorizes each operation, verifies its external approval and binds
// the full request to the selected key and network before signing. Key storage,
// freeze, expiry and replay protection belong to the merchant's service. SDK
// validation checks format; it does not authorize a payment.
//
// Keep private keys inside the key process and clear caller-owned buffers after
// use. Go does not guarantee erasure of every secret copy from process memory.
package signer
