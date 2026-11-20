// Package signer inspects and signs prepared CryptoChief transactions offline.
// It supports EVM, Bitcoin, Litecoin, Bitcoin Cash, Dogecoin, TRON, TON,
// XRP Ledger and Solana.
//
// Pass the nested request of an authenticated wallet.signature.requested event
// to [DecodeSigningRequest]. Call [SigningRequest.Inspect] with the expected
// public [Wallet] to read all recipients, assets and amounts before approval.
// [InspectTransfer] accepts an SDK [Request] and [InspectionContext] directly.
// For digest requests, inspection verifies the corresponding source transaction.
//
// [GenerateWallet] returns a public wallet and a separate private key.
// [DeriveWallet] reconstructs the public record from an existing key.
// After approval, [Sign] signs a request and [SignBatch] signs a batch with one
// key. [SignTRONMessage] signs TIP-191 messages. SDK v2 uses signing contract 1.
package signer
