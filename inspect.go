package signer

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
)

var (
	ErrMalformed   = errors.New("malformed transfer data")
	ErrUnsupported = errors.New("unsupported transfer operation")
	ErrContext     = errors.New("inspection requires valid source context")
	ErrSender      = errors.New("transfer sender differs from the selected wallet")
	ErrMismatch    = errors.New("source transaction does not match the signing digest")
)

// InspectionContext supplies source bytes omitted by some signing formats.
// PreviousTransactions are complete funding transactions, addressed by txid.
// RecipientOwner and TokenMint are optional expectations from the caller's own order.
type InspectionContext struct {
	PayloadHex           string   `json:"source_payload_hex,omitempty"`
	InputIndex           *uint32  `json:"input_index,omitempty"`
	PreviousTransactions []string `json:"previous_transactions,omitempty"`
	RecipientOwner       string   `json:"recipient_owner,omitempty"`
	TokenMint            string   `json:"token_mint,omitempty"`
}

// Asset identifies a native coin, a contract, a jetton wallet or an issued currency.
// The token symbol and decimals are not supplied by most signing formats.
type Asset struct {
	Kind     string `json:"kind"`
	Contract string `json:"contract,omitempty"`
	Currency string `json:"currency,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
}

type Transfer struct {
	From                          string  `json:"from"`
	To                            string  `json:"to"`
	ToRole                        string  `json:"to_role,omitempty"`
	AmountAtomic                  string  `json:"amount_atomic,omitempty"`
	AmountDecimal                 string  `json:"amount_decimal,omitempty"`
	Asset                         Asset   `json:"asset"`
	SourceAccount                 string  `json:"source_account,omitempty"`
	DestinationAccount            string  `json:"destination_account,omitempty"`
	DestinationTag                *uint32 `json:"destination_tag,omitempty"`
	Memo                          string  `json:"memo,omitempty"`
	AttachedNativeAtomic          string  `json:"attached_native_atomic,omitempty"`
	ForwardNativeAtomic           string  `json:"forward_native_atomic,omitempty"`
	FeeAtomic                     string  `json:"fee_atomic,omitempty"`
	FeeLimitAtomic                string  `json:"fee_limit_atomic,omitempty"`
	ComputeUnitLimit              uint32  `json:"compute_unit_limit,omitempty"`
	ComputeUnitPriceMicroLamports string  `json:"compute_unit_price_micro_lamports,omitempty"`
	CreatesDestinationAccount     bool    `json:"creates_destination_account,omitempty"`
}

// Inspection describes the signed instructions, before fees and execution.
// PayloadDigest is the digest the verifier must bind in its approval.
type Inspection struct {
	ChainFamily   Family     `json:"chain_family"`
	ChainID       string     `json:"chain_id,omitempty"`
	PayloadDigest string     `json:"payload_digest"`
	FeeAtomic     string     `json:"fee_atomic,omitempty"`
	Transfers     []Transfer `json:"transfers"`
}

// InspectTransfer reads a signing request using public data only. It refuses
// unknown operations and never returns a partial list of payments. Wallet is
// the independently selected public wallet that will be used to sign.
func InspectTransfer(req Request, wallet Wallet, ctx InspectionContext) (Inspection, error) {
	var zero Inspection
	if wallet.Family != req.Family || wallet.Address == "" || wallet.PublicKeyHex == "" {
		return zero, ErrSender
	}
	digest, err := RequestDigest(req)
	if err != nil {
		return zero, ErrMalformed
	}
	payload, _ := hex.DecodeString(req.PayloadHex) // validated by RequestDigest
	var transfers []Transfer
	var fee string
	switch req.Family {
	case BTC, BTCTestnet, LTC, LTCTestnet, BCH, BCHTestnet, DOGE, DOGETestnet:
		if ctx.RecipientOwner != "" || ctx.TokenMint != "" {
			return zero, ErrContext
		}
		transfers, fee, err = inspectUTXO(req, payload, wallet, ctx)
	default:
		if ctx.InputIndex != nil || len(ctx.PreviousTransactions) != 0 {
			return zero, ErrContext
		}
		if req.Family != Solana && (ctx.RecipientOwner != "" || ctx.TokenMint != "") {
			return zero, ErrContext
		}
		if req.PayloadType == Digest {
			payload, err = verifiedSource(req.Family, payload, ctx.PayloadHex)
			if err != nil {
				return zero, err
			}
		} else if ctx.PayloadHex != "" {
			return zero, ErrContext
		}
		switch req.Family {
		case EVM:
			transfers, err = inspectEVM(payload, wallet)
		case TRON:
			transfers, err = inspectTRON(payload, wallet)
		case TON:
			transfers, err = inspectTON(payload, wallet)
		case XRP, XRPTestnet:
			transfers, err = inspectXRP(req, payload, wallet, ctx)
		case Solana:
			transfers, err = inspectSolana(req, payload, wallet, ctx)
		default:
			err = ErrUnsupported
		}
	}
	if err != nil {
		return zero, err
	}
	if len(transfers) == 0 {
		return zero, ErrUnsupported
	}
	return Inspection{ChainFamily: req.Family, ChainID: req.ChainID, PayloadDigest: digest, FeeAtomic: fee, Transfers: transfers}, nil
}

func verifiedSource(family Family, digest []byte, source string) ([]byte, error) {
	if len(source) == 0 || len(source) > 2*MaxPayloadBytes {
		return nil, ErrContext
	}
	raw, err := hex.DecodeString(source)
	if err != nil {
		return nil, ErrMalformed
	}
	var computed []byte
	switch family {
	case TRON:
		hash := sha256.Sum256(raw)
		computed = hash[:]
	case XRP, XRPTestnet:
		hash := sha512.New()
		hash.Write([]byte{0x53, 0x54, 0x58, 0})
		hash.Write(raw)
		computed = hash.Sum(nil)[:32]
	case TON:
		computed, err = tonCellDigest(raw)
		if err != nil {
			return nil, ErrMalformed
		}
	default:
		return nil, ErrUnsupported
	}
	if !bytes.Equal(computed, digest) {
		return nil, ErrMismatch
	}
	return raw, nil
}
