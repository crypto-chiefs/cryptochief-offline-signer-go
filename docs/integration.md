# Integrate the Go SDK into a Non-Custodial Signing Service

## Transaction flow

1. Crypto Chief prepares the unsigned transaction or per-input signing hashes.
2. The merchant service verifies the request, payment intent and key permissions.
3. The isolated key process calls `Sign` or `SignBatch` with the approved payload.
4. Crypto Chief attaches the returned signatures, broadcasts and tracks the transaction.

This library supplies the local cryptographic operations. The HTTP contract,
transaction-preparation endpoint and callback integration are separate components.
The SDK is not a drop-in implementation of the processing client's `Transactions.Sign` API.

## Wallet generation and storage

See [wallet generation](wallets.md) for method signatures, options and examples.

Generate new wallets with `GenerateWallet`. Store the returned private key through
the key process; register only the public `Wallet` data. Keep project, network,
key ID/version and wallet role in the registry.

Before signing, call `DeriveWallet` and compare its address and public key against
the trusted registry. Reuse the original `WalletOptions`, including TON address flags.

| Key family | Accepted bytes |
|---|---|
| EVM, Bitcoin, Litecoin, Bitcoin Cash, Dogecoin, TRON, XRP Ledger | A valid 32-byte secp256k1 scalar |
| TON, Solana | A 32-byte Ed25519 seed, or a consistent 64-byte `seed ‖ public key` |

Keys are raw bytes, not hex/base64 strings. Key format must be explicit in storage
metadata; decode a known storage encoding before calling the SDK. Do not trim,
pad or infer formats from key contents.

The SDK neither stores nor modifies the caller's key buffer. Clear that buffer
after use. Go does not guarantee removal of every temporary copy from memory.
Vault/KMS access, process isolation, key lifecycle, audit logs and recovery belong
to the merchant service. Provision new keys for this integration; do not import
keys from the previous signing service.

## Request approval

The external verifier must approve the complete canonical SDK request and bind:

- Request ID, project and key ID/version.
- Network, operation type and wallet permissions.
- Issued-at and expiry times.
- The canonical request bytes or `RequestDigest`.

Use `DecodeRequest`, then `CanonicalRequest` or `RequestDigest`. Verify the
approval signature and all bindings before signing. Recheck the request digest
immediately before `Sign`; do not change the approved request.

The verifier checks amounts, recipients, contract calls, memo/tag and fees against
the payment intent. A precomputed digest does not expose those fields to the SDK.
Approving only `payload_hex` leaves fields such as EVM `chain_id` unbound.

For `SignBatch`, approve every ordered request and the batch context. For
`SignTRONMessage`, bind the exact message, prefix mode and `operation_type=message`.
A transaction permission does not authorize message signing. The SDK payload
type `digest` is a byte format; operation permissions are checked separately.

Replay protection, idempotency, freeze rules, receipts and administrator approvals
are enforced by the merchant service.

## Attach signatures in Crypto Chief

| Family | Assembly rule |
|---|---|
| EVM | Prepare unsigned binary bytes for `EVMTransaction`; apply R‖S‖V with `Transaction.WithSignature` using the same chain ID |
| Bitcoin, Litecoin, Bitcoin Cash, Dogecoin | Insert each signature and public key into the corresponding input's script or witness; use the required sighash byte |
| TRON | Attach the R‖S‖V signature to the transaction containing the original `raw_data` |
| TON | Insert the Ed25519 signature into the wallet message built from the original signing cell |
| XRP Ledger | Add the DER signature to the transaction whose unsigned serialization was approved |
| Solana | Insert the Ed25519 signature into the matching signer's slot without changing the compiled message |

The existing EVM service request uses JSON fields. Its adapter must serialize them
before calling the SDK and assemble the signed transaction afterward.

If a TRON wrapper returns `signer_address`, derive it with `DeriveWallet` using
the signing key. The receiving service compares this field when it is nonempty.
The SDK response itself contains `PublicKeyHex`.

Only TIP-191 clients that require TronLink's signature format convert recovery
byte `0/1` to `27/28`. Transaction signatures retain `0/1`.

## TON memos and XRP destination tags

Crypto Chief places the TON comment or XRP DestinationTag in the unsigned payload.
The verifier approves those fields before signing. Do not edit them afterward.
For XRP, no tag and tag `0` are distinct. X-address network flags must match the
selected network before conversion to a classic address.

The current builder supports numeric XRP DestinationTag, not textual XRPL `Memos`.

## Offline deployment

Prepare the application, dependencies and Go toolchain before network isolation.
Use vendored dependencies with `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`
and `-mod=vendor`. Run [verify.sh](../verify.sh) on Linux or
[verify.ps1](../verify.ps1) in PowerShell to check SDK imports, builds and tests.

Wallet registration, balance queries, transaction status and monitoring use the
[Processing Go SDK](https://github.com/crypto-chiefs/cryptochief-crypto-processing-go)
in a separate network-enabled component.

[SDK overview](../README.md) · [Wallet generation](wallets.md) · [Signing reference](signing.md)
