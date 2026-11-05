# Crypto Chief Go SDK — Offline Wallets & Transaction Signing

**Crypto Chief Offline Signer** is a Go (Golang) library for offline cryptocurrency
wallet generation and transaction signing. It supports **EVM, Bitcoin, Litecoin,
Bitcoin Cash, Dogecoin, TRON, TON, XRP Ledger and Solana** without network requests.
EVM networks include Ethereum, BNB Smart Chain, Polygon, Arbitrum, Optimism and Avalanche C-Chain.

Use it in a merchant's non-custodial signing service. Crypto Chief prepares the
transaction, the merchant approves it, the SDK signs it, and Crypto Chief attaches
the signature and broadcasts the transaction.

- Generate private keys and blockchain addresses locally.
- Derive addresses and public keys from an existing key buffer.
- Sign prepared transactions, UTXO input hashes and TRON TIP-191 messages.
- Validate signing requests and compute their canonical approval digest.
- Build from vendored dependencies in a network-isolated environment.

Requires **Go 1.24.3+**. SDK version: `0.1.0`. Signing contract: `1`.

[Quick start](#quick-start) · [Supported blockchains](#supported-blockchains) ·
[Wallet generation](docs/wallets.md) ·
[Signing reference](docs/signing.md) · [Integration guide](docs/integration.md)

## Install

Run from your application's Go module directory:

```sh
go get github.com/crypto-chiefs/cryptochief-offline-signer-go@latest
```

Import the package as `signer`:

```go
import signer "github.com/crypto-chiefs/cryptochief-offline-signer-go"
```

For offline deployment, install dependencies before network isolation. After
adding your imports, run `go mod tidy` and `go mod vendor`. Transfer the application
with `go.mod`, `go.sum`, `vendor` and the Go toolchain; build with `-mod=vendor`.

## Quick start

Generate a Bitcoin SegWit wallet and verify its public record:

```go
package main

import (
    "fmt"

    signer "github.com/crypto-chiefs/cryptochief-offline-signer-go"
)

func main() {
    options := signer.WalletOptions{Family: signer.BTC}
    wallet, privateKey, err := signer.GenerateWallet(options)
    if err != nil {
        panic(err)
    }
    defer clear(privateKey)

    restored, err := signer.DeriveWallet(options, privateKey)
    if err != nil {
        panic(err)
    }
    if restored.Address != wallet.Address || restored.PublicKeyHex != wallet.PublicKeyHex {
        panic("wallet mismatch")
    }
    fmt.Println(wallet.Address)
}
```

This example creates a temporary wallet. In a signing service, store the private
key securely before registering the public wallet record. `Wallet` contains no
private key; the separate secret result is always 32 raw bytes.

See [wallet generation](docs/wallets.md) for options, return fields, testnet formats
and verification of stored keys.

## Supported blockchains

| Family | Go constant | Wallet address |
|---|---|---|
| EVM: Ethereum, BNB Smart Chain, Polygon, Arbitrum, Optimism, Avalanche C-Chain | `EVM` | EIP-55 |
| Bitcoin | `BTC` | Native SegWit P2WPKH, `bc1` |
| Litecoin | `LTC` | Native SegWit P2WPKH, `ltc1` |
| Bitcoin Cash | `BCH` | P2PKH CashAddr, `bitcoincash:` |
| Dogecoin | `DOGE` | P2PKH Base58Check |
| TRON | `TRON` | Base58Check, `T…` |
| TON | `TON` | V4R2, workchain 0, subwallet ID 698983191 |
| XRP Ledger | `XRP` | Classic `r…` address, secp256k1 |
| Solana | `Solana` | Base58 Ed25519 public key |

Testnet constants: `BTCTestnet`, `LTCTestnet`, `BCHTestnet`, `DOGETestnet`,
`XRPTestnet`. EVM, TRON and Solana retain their family identifiers across mainnets and testnets.
For TON, set `WalletOptions.TONTestnet`; `TONNonBounceable` selects a non-bounceable
address. Both flags affect the address representation, not the TON account ID.

The merchant service binds each key to its network. Wallet roles such as master,
transit and static are registry metadata.

## Sign a prepared transaction

Pass the approved JSON request and the corresponding raw private key to the SDK:

```go
package merchantsigner

import signer "github.com/crypto-chiefs/cryptochief-offline-signer-go"

// SignApprovedPayload requires prior authorization of the complete request,
// network, operation and key binding by the merchant service.
func SignApprovedPayload(rawJSON, privateKey []byte) (signer.Signature, error) {
    request, err := signer.DecodeRequest(rawJSON)
    if err != nil {
        return signer.Signature{}, err
    }
    return signer.Sign(request, privateKey)
}
```

`DecodeRequest` rejects malformed payloads, unknown or duplicate fields, nulls
and trailing JSON. It does not authorize a payment. `Sign` returns the signature
and public verification data; Crypto Chief assembles the signed transaction.

For multiple UTXO inputs, use `SignBatch(requests, privateKey)`: one prepared
sighash per input, one key per batch. Results retain input order. Any error
returns no signatures.

See the [payload and response formats](docs/signing.md) and
[merchant approval contract](docs/integration.md#request-approval).

## TRON message signing

`SignTRONMessage(message, prefixMode, privateKey)` signs TIP-191 messages.
Choose `TRONPrefixV2` or `TRONPrefixLegacy32` explicitly. Messages are literal
UTF-8, up to 512 bytes; hex-looking text is not decoded.

The returned recovery byte is `0` or `1`. A TronLink-compatible message signature
uses `27` or `28`; convert that byte in the calling application.

## API reference

| Function | Result |
|---|---|
| `GenerateWallet(options)` | Public `Wallet` and a separate 32-byte private key |
| `DeriveWallet(options, privateKey)` | Address and public key for registry verification |
| `Sign(request, privateKey)` | Signature for one prepared payload |
| `SignBatch(requests, privateKey)` | Ordered signatures using one key |
| `DecodeRequest(rawJSON)` | Strictly decoded and validated `Request` |
| `ValidateRequest(request)` | Payload validation without a private key |
| `CanonicalRequest(request)` | Canonical JSON bytes for request approval |
| `RequestDigest(request)` | SHA-256 of the complete canonical request |
| `TRONMessageDigest(message, prefixMode)` | TIP-191 signing digest |
| `SignTRONMessage(message, prefixMode, privateKey)` | TIP-191 signature |

Private keys are raw 32-byte secp256k1 scalars or Ed25519 seeds. TON and Solana
also accept a consistent 64-byte Ed25519 private key. The SDK does not decode
hex/base64 keys, pad short keys or modify the caller's key buffer.

## Build without network access

On Linux, run from the SDK directory:

```sh
sh ./verify.sh
```

On Windows, use PowerShell:

```powershell
./verify.ps1
```

Both scripts reject network and process-launch imports, build
for Windows/Linux amd64 with CGO disabled, and run tests and `go vet` on the host.

For a standalone SDK build on a POSIX shell:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off GOFLAGS= CGO_ENABLED=0 go build -mod=vendor ./...
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off GOFLAGS= CGO_ENABLED=0 go test -mod=vendor ./...
```

Network isolation of the signing process is an OS policy; the SDK's checks
verify code and dependencies.

## FAQ

### Does the SDK make RPC, HTTP or internal network requests?

No. Wallet generation, derivation, hashing and signing are local operations.
The package has no network client, key storage, environment configuration or logging.

### Who builds and broadcasts transactions?

Crypto Chief. Fee estimation, nonce/UTXO/seqno/blockhash selection, transaction
assembly, broadcast and confirmation tracking remain outside this library.

### Are TON memos and XRP destination tags supported?

TON comments and XRP destination tags are included in the prepared payload.
The SDK signs those bytes without replacing the memo or tag. The current
transaction builder supports XRP DestinationTag, including zero, but does not
create textual XRPL `Memos`.

### Does signing validate the amount or recipient?

The merchant's verifier checks payment intent before signing. The SDK validates
its request format and cryptographic inputs. It cannot recover payment details
from a precomputed digest.

## Documentation

- [Wallet generation](docs/wallets.md): methods, address formats, TON options and key verification.
- [Signing reference](docs/signing.md): fields, payload types, signatures and limits.
- [Integration guide](docs/integration.md): approvals, key handling and transaction assembly.
- [Runnable Go examples](example_test.go): wallet generation, prepared signing and TIP-191.
- [Crypto Chief Processing Go SDK](https://github.com/crypto-chiefs/cryptochief-crypto-processing-go): network API client for payments, payouts and wallet management.
