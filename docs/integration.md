# Integrate a merchant signer

## Receive a signing request

1. Verify the webhook signature over the original body. Check `event`, `request_id`, `expires_at`, `project_id` and `network` against the expected operation.
2. Read the nested `request` as `json.RawMessage` and pass it to `DecodeSigningRequest`. Choose the expected public wallet from the merchant's registry.
3. Call `prepared.Inspect(wallet)`. Compare every transfer, fee and token identifier with the order. For digest inputs, inspection uses the source context supplied with the request. [Transfer inspection](inspection.md)
4. After approval, call `Sign(prepared.Request, privateKey)`. Submit the result to the completion endpoint with the original `request_id` before expiry. Through White Label, use that installation's Merchant API.

## Wallet generation and storage

Store the private key returned by `GenerateWallet` in the signing service. Register its public `Wallet` with the project, network and key identifier. Use `DeriveWallet` with the original options to verify the public record when loading an existing key. [Wallet generation](wallets.md)

## Request approval

`Inspection.PayloadDigest` equals `RequestDigest(prepared.Request)`. Record the digest with the approved operation, project, network, key, request ID and expiry. If the verifier and signing process are separate, the signing process must recompute the digest before using the key. For UTXO batches, approve each input and verify the output list for the transaction.

The application handles webhook authentication, replay protection and retries. On a repeated delivery for the same approved request, reuse the recorded result.

## Return the signature

Post `request_id` and `result` to `/v1/wallets/signatures/complete`.

| Family | `result` contents |
| --- | --- |
| EVM | Attach the SDK's 65-byte signature to the same unsigned transaction with the original chain ID. Return the complete serialized transaction in `signed_tx.signed_tx_hex` with a `0x` prefix. |
| TRON | Set `signature.signature_hex` to the 65-byte transaction signature including recovery byte `0` or `1`. |
| Bitcoin, Litecoin, Bitcoin Cash, Dogecoin, XRP Ledger | Set `signature.signature_hex` to the DER signature from `SignatureHex`. For UTXO callbacks, leave the sighash byte out of the signature. |
| TON, Solana | Set `signature.signature_hex` to the 64-byte Ed25519 signature from `SignatureHex`. |

## Offline build

In the application module, run `go mod tidy` and `go mod vendor` before isolating the signing process. Build with `go build -mod=vendor ./...`. To verify the SDK checkout, run [verify.sh](../verify.sh) on Linux or [verify.ps1](../verify.ps1) in PowerShell.

[SDK overview](../README.md) · [Signing formats](signing.md)
