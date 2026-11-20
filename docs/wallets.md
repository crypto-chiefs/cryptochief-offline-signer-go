# Generate Crypto Wallets in Go

`GenerateWallet` creates a private key and wallet address locally.
`DeriveWallet` restores the public wallet record from a private key.
Neither method registers an address, deploys a wallet contract or makes network requests.

## Methods

```go
func GenerateWallet(options WalletOptions) (Wallet, []byte, error)
func DeriveWallet(options WalletOptions, privateKey []byte) (Wallet, error)
```

Each `GenerateWallet` call creates a new key using the operating system's
cryptographic random source. The second return value is the private key, separate
from the public `Wallet`. To reproduce an address, use `DeriveWallet` with the
same key and options.

## Generate a wallet

```go
package main

import (
    "encoding/json"
    "fmt"

    signer "github.com/crypto-chiefs/cryptochief-offline-signer-go/v2"
)

func main() {
    wallet, privateKey, err := signer.GenerateWallet(signer.WalletOptions{
        Family: signer.EVM,
    })
    if err != nil {
        panic(err)
    }
    defer clear(privateKey)

    publicJSON, err := json.Marshal(wallet)
    if err != nil {
        panic(err)
    }
    fmt.Println(string(publicJSON))
}
```

The example prints only public data and discards the key on exit. In a signing
service, securely store `privateKey` before registering `wallet`.

## WalletOptions

| Go field | JSON field | Type | Default / rule |
|---|---|---|---|
| `Family` | `chain_family` | `Family` | Required; one of the constants below |
| `TONTestnet` | `ton_testnet` | `bool` | `false`; TON test-only address flag |
| `TONNonBounceable` | `ton_non_bounceable` | `bool` | `false`; TON defaults to a bounceable address |

Setting either TON flag to `true` for another family returns an error.
Network, project, key ID and wallet role are stored by the calling service.

## Families and address formats

Use these constants from the `signer` package:

| Blockchain family | Mainnet constant | Testnet constant | Address format | `AddressType` |
|---|---|---|---|---|
| EVM | `EVM` | `EVM` | EIP-55 | `eip55` |
| Bitcoin | `BTC` | `BTCTestnet` | P2WPKH: `bc1` / `tb1` | `p2wpkh` |
| Litecoin | `LTC` | `LTCTestnet` | P2WPKH: `ltc1` / `tltc1` | `p2wpkh` |
| Bitcoin Cash | `BCH` | `BCHTestnet` | CashAddr: `bitcoincash:` / `bchtest:` | `cashaddr-p2pkh` |
| Dogecoin | `DOGE` | `DOGETestnet` | P2PKH Base58Check, version `0x1e` / `0x71` | `p2pkh` |
| TRON | `TRON` | `TRON` | Base58Check, `T…` | `base58check` |
| TON | `TON` | `TON` + `TONTestnet: true` | V4R2 user-friendly address | `v4r2` |
| XRP Ledger | `XRP` | `XRPTestnet` | Classic `r…` address | `classic` |
| Solana | `Solana` | `Solana` | Base58 Ed25519 public key | `ed25519` |

EVM includes Ethereum, BNB Smart Chain, Polygon, Arbitrum, Optimism and Avalanche
C-Chain. The same key produces the same EVM address across these networks;
wallet generation does not take a chain ID.

XRP generation returns a classic address without a destination tag. Mainnet and
testnet use the same classic address format. Bitcoin's `tb1` format does not
distinguish testnet from signet; bind the intended network in your registry.

The exact `chain_family` strings are listed in the [signing reference](signing.md#families-and-payloads).

## TON options

For a non-bounceable testnet address, pass:

```go
signer.WalletOptions{
    Family:           signer.TON,
    TONTestnet:       true,
    TONNonBounceable: true,
}
```

TON wallets use V4R2, workchain `0` and subwallet ID `698983191`. These values
are fixed. Both flags change address representation only; the account ID stays
the same. Reuse the original flags when comparing addresses with your registry.

## Wallet result

| Go field | JSON field | Content |
|---|---|---|
| `Family` | `chain_family` | Requested family, including any testnet alias |
| `Address` | `address` | Address in the selected format |
| `PublicKeyHex` | `public_key_hex` | Hex-encoded public key without `0x` |
| `AddressType` | `address_type` | Format identifier from the table above |
| `TONSubwalletID` | `ton_subwallet_id` | `698983191` for TON; omitted from JSON for other families |

Public keys are compressed 33-byte secp256k1 keys for EVM, Bitcoin, Litecoin,
Bitcoin Cash, Dogecoin, TRON and XRP Ledger; 32-byte Ed25519 keys for TON and Solana.
`Wallet` contains no secret fields.

## Private key format

| Family | Generated key | Accepted by `DeriveWallet` |
|---|---|---|
| EVM, Bitcoin, Litecoin, Bitcoin Cash, Dogecoin, TRON, XRP Ledger | 32-byte secp256k1 scalar | Valid 32-byte scalar |
| TON, Solana | 32-byte Ed25519 seed | 32-byte seed or consistent 64-byte `seed ‖ public key` |

Keys are raw bytes. The SDK does not decode hex, Base64 or WIF, trim or pad keys,
or generate mnemonic phrases and HD derivation paths. The returned key can be
passed directly to `Sign` with a request for the same family.

## Verify a stored key

After decrypting a key, derive its public record and compare it with the registry:

```go
package wallets

import (
    "errors"

    signer "github.com/crypto-chiefs/cryptochief-offline-signer-go/v2"
)

func CheckWallet(options signer.WalletOptions, privateKey []byte, expected signer.Wallet) error {
    actual, err := signer.DeriveWallet(options, privateKey)
    if err != nil {
        return err
    }
    if actual != expected {
        return errors.New("wallet does not match registry")
    }
    return nil
}
```

`DeriveWallet` does not change or retain the key buffer. The caller clears it
after use. Key storage and access rules are covered in the [integration guide](integration.md#wallet-generation-and-storage).

## Errors

| Condition | Result |
|---|---|
| Missing or unsupported family | Error |
| TON flags enabled for another family | Error |
| secp256k1 key has the wrong length, is zero or exceeds the valid scalar range | Error |
| Ed25519 key is neither 32 nor 64 bytes | Error |
| 64-byte Ed25519 key has a public half inconsistent with its seed | Error |

On error, `GenerateWallet` returns an empty `Wallet` and a nil key;
`DeriveWallet` returns an empty `Wallet`. Check `err` before using the result.

[SDK overview](../README.md) · [Signing reference](signing.md) · [Integration guide](integration.md)
