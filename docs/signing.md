# Go Offline Signing API Reference

Use `DecodeSigningRequest` for the nested `request` in a processing webhook.
Use `DecodeRequest` for the SDK JSON format below. SDK v2 uses version 1 of
this format. Private keys are passed separately to `Sign`.
[Inspect a transfer before signing](inspection.md)

## Request fields

| JSON field | Go field | Type | Rule |
|---|---|---|---|
| `version` | `Version` | integer | Required; `1` |
| `chain_family` | `Family` | string | Required; one of the family identifiers below |
| `payload_type` | `PayloadType` | string | Required; valid for the selected family |
| `payload_hex` | `PayloadHex` | string | Required; nonempty, even-length hex, no `0x` prefix |
| `chain_id` | `ChainID` | string | Required for EVM; positive decimal, no leading zeros, at most 256 bits; omit otherwise |
| `hash_type` | `HashType` | uint32 | Required for UTXO: `1`, or `65` for BCH; omit otherwise |

`DecodeRequest` accepts one UTF-8 JSON object. Field names are case-sensitive;
unknown fields, duplicate names (including escaped equivalents), missing required
fields, nulls and trailing data are rejected.

Example request for one Bitcoin input. The digest is synthetic test data:

```json
{
  "version": 1,
  "chain_family": "BTC_UTXO",
  "payload_type": "digest",
  "payload_hex": "4200000000000000000000000000000000000000000000000000000000000000",
  "hash_type": 1
}
```

## Families and payloads

| Family identifier | Payload type / Go constant | Prepared input | Signature |
|---|---|---|---|
| `EVM` | `evm_transaction` / `EVMTransaction` | Unsigned binary legacy or EIP-1559 transaction | secp256k1 R‖S‖V, 65 bytes |
| `BTC_UTXO`, `LITECOIN_UTXO`, `DOGECOIN_UTXO` | `digest` / `Digest` | 32-byte sighash for one input; `hash_type=1` | Low-S secp256k1 DER |
| `BTC_CASH_UTXO` | `digest` / `Digest` | 32-byte BCH ForkID sighash for one input; `hash_type=65` | Low-S secp256k1 DER |
| `TRON` | `tron_raw_data` / `TRONRawData`, or `digest` / `Digest` | Protobuf `raw_data`, or its SHA-256 hash | secp256k1 R‖S‖V, 65 bytes |
| `TON` | `ton_cell` / `TONCell`, or `digest` / `Digest` | BOC of the signing cell, or its 32-byte cell hash | Ed25519 over the cell hash |
| `XRP_LEDGER` | `xrp_blob` / `XRPBlob`, or `digest` / `Digest` | Unsigned signing serialization without STX, or SHA512Half(STX‖blob) | Low-S secp256k1 DER |
| `SOLANA` | `solana_message` / `SolanaMessage` | Exact compiled transaction message | Ed25519 over the message |

Testnet identifiers: `BTC_UTXO_TESTNET`, `LITECOIN_UTXO_TESTNET`,
`BTC_CASH_UTXO_TESTNET`, `DOGECOIN_UTXO_TESTNET`, `XRP_LEDGER_TESTNET`.
Other networks use the same family identifier. The response preserves the
requested identifier.

### EVM

The transaction must have `v=r=s=0`. The `chain_id` request field must match the
embedded chain ID of an EIP-1559 transaction. Type 1 access-list, blob and set-code
transactions are not supported. The SDK does not calculate gas, fees, nonce,
value or calldata.

### Bitcoin, Litecoin, Bitcoin Cash and Dogecoin

Crypto Chief computes each input's sighash. `SignBatch` signs all supplied
requests with one key and retains input order. Other sighash modes are rejected.
Use `WithHashTypeHex` when assembling an input that needs the appended sighash byte.

### TON

The BOC must contain one complete root graph of ordinary cells. Multiple roots,
trailing bytes, unreachable cells, cycles, exotic cells, stored hashes and cache
bits are rejected. CRC and indexed BOCs are supported. A cell hash is not
`SHA256(BOC)`.

### XRP Ledger

For `xrp_blob`, the SDK prepends STX (`53 54 58 00`) exactly once before hashing.
For `digest`, supply the final 32-byte SHA-512Half value.

### Solana

Supply the compiled message, not a full signed transaction or a SHA-256 digest.
`solana_message` is a transaction payload format, not a wallet-login protocol.

## Signature fields

| JSON field | Go field | Content |
|---|---|---|
| `version` | `Version` | `1` |
| `chain_family` | `Family` | Requested family identifier |
| `algorithm` | `Algorithm` | `secp256k1-rsv`, `secp256k1-der` or `ed25519` |
| `public_key_hex` | `PublicKeyHex` | Compressed secp256k1 key (33 bytes) or Ed25519 key (32 bytes) |
| `signature_hex` | `SignatureHex` | Signature bytes encoded as hex |
| `signature_base64` | `SignatureBase64` | The same signature encoded as standard Base64 |
| `digest_hex` | `DigestHex` | Blockchain signing digest; omitted for Solana |
| `signature_with_hashtype_hex` | `WithHashTypeHex` | UTXO only: DER signature followed by `01`, or `41` for BCH |

Recoverable signatures use `V=0/1`. The response contains no private key,
transaction bytes or transaction hash. `Sign` returns a zero-value `Signature`
on error; `SignBatch` returns no partial result.

## Request approval digest

`CanonicalRequest` validates the request and returns JSON without whitespace in
this field order: `version`, `chain_family`, `payload_type`, `payload_hex`,
`chain_id`, `hash_type`. Empty `chain_id` and zero `hash_type` are omitted.
String spelling is retained, including hex letter case.

`RequestDigest` returns the lowercase hex SHA-256 of those canonical bytes.
It binds the complete SDK request, including EVM chain ID and UTXO hash type.
It is distinct from `Signature.DigestHex`, which is the blockchain signing digest.
See [request approval](integration.md#request-approval) for the outer authorization fields.

## TRON TIP-191 messages

`TRONMessageDigest(message, prefixMode)` returns a 32-byte Keccak-256 digest.
`SignTRONMessage` signs the same digest with secp256k1.

| Prefix mode | Bytes hashed before the literal UTF-8 message |
|---|---|
| `TRONPrefixV2` (`v2`) | `\x19TRON Signed Message:\n` + decimal byte length |
| `TRONPrefixLegacy32` (`legacy32`) | `\x19TRON Signed Message:\n32` |

The message must contain non-whitespace content. Printable UTF-8 plus tab,
carriage return and newline are accepted. Message text is neither trimmed nor
hex-decoded. The prefix mode is required.

## Limits

| Input | Limit |
|---|---|
| Decoded payload | 1 MiB per request, all families |
| `digest` payload | Exactly 32 bytes |
| Batch | 1–4096 requests; at most 8 MiB of decoded payloads |
| Request JSON | `2 × MaxPayloadBytes + 4096` bytes |
| EVM chain ID | Positive integer, at most 78 decimal digits and 256 bits |
| TON BOC | At most 16384 cells; depth at most 1023 |
| TRON message | At most 512 UTF-8 bytes |

These are SDK input limits. They do not replace a network's transaction-size
or execution rules.

[SDK overview](../README.md) · [Wallet generation](wallets.md) · [Integration guide](integration.md)
