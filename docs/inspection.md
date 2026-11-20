# Transfer inspection

Use `DecodeSigningRequest(event.Request)` on the nested request from an authenticated CryptoChief signing webhook, then call `prepared.Inspect(wallet)`. The method checks the declared address against the wallet selected from your registry. When working with the SDK signing format directly, use `InspectTransfer(req, wallet, ctx)`.

## Read the result

| Field | Meaning |
| --- | --- |
| `Inspection.ChainFamily`, `ChainID` | The signing family and, for EVM, the decimal chain ID. |
| `Inspection.Transfers` | All recognized outgoing payments. UTXO outputs include change. |
| `Transfer.From`, `To` | Sender and intended recipient. For unsigned EVM, the selected public wallet determines the sender. If `ToRole` is `token_account`, the Solana destination is a token account. |
| `Transfer.AmountAtomic`, `AmountDecimal` | Exact strings. `AmountAtomic` counts base units. XRP issued amounts use `AmountDecimal`. |
| `Transfer.Asset` | `native`, `token` with contract address or mint, `jetton_wallet` with the sender's jetton wallet address, or `issued` with currency and issuer. Match the identifier against the asset accepted for the order. |
| `Inspection.PayloadDigest` | SHA-256 of the canonical SDK request. Use it to bind approval to the exact request passed to `Sign`. |

Token symbols and decimals come from your asset registry. Keep amounts as strings or exact integers/decimals. An empty fee field means the fee is unknown. UTXO reports the whole transaction fee in `Inspection.FeeAtomic`, XRP reports the fee in drops in `Transfer.FeeAtomic`, EVM reports the gas cost ceiling in `Transfer.FeeLimitAtomic`, and TRON reports the encoded fee limit when present.

## Source data by chain

For SDK requests with `payload_type: "digest"`, pass the public source bytes in `InspectionContext` as shown below. The inspector recomputes the signing digest before returning transfers. A digest on its own does not identify a recipient, amount or asset.

| Family | Input and checks |
| --- | --- |
| EVM | Unsigned legacy or type 2 transaction. For a direct ERC-20 `transfer(address,uint256)`, `To` is the token recipient and `Asset.Contract` is the contract called. Arbitrary contract calls and contract creation are unsupported. |
| Bitcoin, Litecoin, Bitcoin Cash, Dogecoin | For each input, supply the same unsigned transaction as `source_payload_hex`, its zero-based `input_index`, and one full raw transaction in `previous_transactions` for each distinct funding txid. All inputs must belong to the selected wallet. Each input review returns the same list of outputs. Count each output once when reviewing the transaction. |
| TRON | A serialized `Transaction.raw`, or its digest with those bytes in `source_payload_hex`. Reads a single native TRX payment or a direct TRC-20 transfer, including any UTF-8 memo. |
| TON | A V4R2 signing cell in BOC format, or its cell hash with the BOC in `source_payload_hex`. Inspect every outgoing message. For jettons, compare the sender's jetton wallet against your wallet-to-master mapping and check attached and forwarded TON (`AttachedNativeAtomic`, `ForwardNativeAtomic`). |
| XRP Ledger | An unsigned, single-signing direct Payment, or its digest with the signing serialization in `source_payload_hex` (omit the STX prefix). Match `DestinationTag` including tag zero. For issued payments, match both `Asset.Currency` and `Asset.Issuer`. |
| Solana | A compiled legacy or v0 message with static accounts. Native transfers, classic SPL Transfer and TransferChecked are supported. If the instructions omit the mint, set `prepared.InspectionContext.TokenMint` from the order. To verify a recipient owner, set `RecipientOwner` from the order. The inspector checks the associated token accounts. Address lookup tables and arbitrary programs are unsupported. |

For Solana, check `CreatesDestinationAccount` and any compute-unit limit and price when applying fee policy. For TON and Solana, execution fees depend on chain state.

## Errors

Inspection returns an empty result on error. Callers can use `errors.Is` with these values.

| Error | Meaning |
| --- | --- |
| `ErrMalformed` | Invalid request or transaction encoding. |
| `ErrUnsupported` | The operation or one of its instructions is outside the supported payment forms. |
| `ErrContext` | Required source bytes or account information are missing, invalid or inapplicable. |
| `ErrSender` | The selected wallet's address or public key does not match the payment. |
| `ErrMismatch` | Source data disagrees with the requested digest or referenced funding transaction. |

[Runnable examples](../example_test.go) · [Signing formats](signing.md)
