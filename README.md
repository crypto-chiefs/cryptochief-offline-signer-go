# CryptoChief Offline Signer for Go

[![Go Reference](https://pkg.go.dev/badge/github.com/crypto-chiefs/cryptochief-offline-signer-go/v2.svg)](https://pkg.go.dev/github.com/crypto-chiefs/cryptochief-offline-signer-go/v2)
[![CI](https://github.com/crypto-chiefs/cryptochief-offline-signer-go/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/crypto-chiefs/cryptochief-offline-signer-go/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Decode a proposed transfer before signing it. The SDK returns the sender, recipients, amounts and assets using the registered public wallet. Wallet generation, inspection and signing run offline.

## Install v2

Requires Go 1.24.3 or later.

```sh
go get github.com/crypto-chiefs/cryptochief-offline-signer-go/v2@v2.0.0
```

To upgrade from v0.x, add `/v2` to Go imports. Keep `"version": 1` in SDK signing requests.

## Inspect a signing request

After verifying a `wallet.signature.requested` webhook, pass its nested `request` object to `DecodeSigningRequest`. Select the public wallet for the project and network from your registry. Inspection requires its address and public key.

```go
package merchant

import signer "github.com/crypto-chiefs/cryptochief-offline-signer-go/v2"

func Preview(requestJSON []byte, wallet signer.Wallet) (signer.Inspection, error) {
    prepared, err := signer.DecodeSigningRequest(requestJSON)
    if err != nil {
        return signer.Inspection{}, err
    }
    return prepared.Inspect(wallet)
}
```

Read **every** entry in `Inspection.Transfers`. Each has `From`, `To`, `Asset` and either `AmountAtomic` (integer base units) or `AmountDecimal` (XRP issued currency). The result describes the unsigned instructions. An unknown operation or a missing source transaction for a digest returns an error.

If you already have a `signer.Request`, call `signer.InspectTransfer(req, wallet, ctx)` directly. Run `go test -run '^ExampleInspectTransfer$'` in this repository for a complete example. [Transfer inspection](docs/inspection.md) · [Example source](example_test.go)

## Supported transfers

| Family | Payments |
| --- | --- |
| EVM | Native coin and direct ERC-20 transfers in legacy and EIP-1559 transactions |
| Bitcoin, Litecoin, Bitcoin Cash, Dogecoin | Native payments and change, mainnet and testnet |
| TRON | TRX and direct TRC-20 transfers |
| TON | V4R2 native transfers and TEP-74 jetton transfers |
| XRP Ledger | Direct XRP and issued-currency payments, mainnet and testnet |
| Solana | Native SOL and classic SPL Token transfers |

EVM, TRON, TON and Solana share their family identifier across networks. Verify the network from the authenticated webhook against the order.

## Generate and sign

`GenerateWallet` returns a public wallet and a separate private key. `DeriveWallet` reconstructs the public record from an existing key. After approval, `Sign` signs one prepared request. `SignBatch` signs multiple requests with the same key. For an EVM callback, the signing service attaches the returned signature and sends the serialized transaction as `signed_tx_hex`.

[Wallet generation](docs/wallets.md) · [Signing formats](docs/signing.md) · [Callback integration](docs/integration.md)

## Verify the build

Run `sh ./verify.sh` on Linux or `./verify.ps1` in PowerShell. The scripts use the vendored dependencies, build for Linux and Windows amd64, run the host tests and run `go vet`.
