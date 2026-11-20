package signer

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// SigningRequest is the public transaction and source evidence carried in the
// request field of a CryptoChief wallet.signature.requested webhook.
type SigningRequest struct {
	Request           Request
	Address           string
	InspectionContext InspectionContext
}

// DecodeSigningRequest converts event.request into a version 1 SDK signing
// payload. The caller verifies the signature over the original webhook body
// and checks its project, network and expiry before using this decoder.
func DecodeSigningRequest(raw []byte) (SigningRequest, error) {
	var zero SigningRequest
	const maxCallback = MaxRequestJSONBytes + 2*(MaxPayloadBytes+MaxBatchPayloadBytes) + 4096
	if len(raw) > maxCallback || !utf8.Valid(raw) {
		return zero, ErrMalformed
	}
	fields, err := readProcessingObject(raw, "chain_family", "address", "tx", "inspection_context")
	if err != nil {
		return zero, err
	}
	if len(fields["tx"]) == 0 || len(fields["tx"]) > MaxRequestJSONBytes {
		return zero, ErrMalformed
	}
	family, err := fields.str("chain_family")
	if err != nil {
		return zero, err
	}
	address, err := fields.str("address")
	if err != nil || len(address) == 0 || len(address) > 255 {
		return zero, fmt.Errorf("%w: invalid address", ErrMalformed)
	}
	for i := range len(address) {
		if address[i] < 0x21 || address[i] > 0x7e {
			return zero, fmt.Errorf("%w: invalid address", ErrMalformed)
		}
	}
	req := Request{Version: 1, Family: Family(family)}
	if req.Family == EVM && !common.IsHexAddress(address) {
		return zero, fmt.Errorf("%w: invalid EVM address", ErrMalformed)
	}
	tx := fields["tx"]
	switch req.Family {
	case EVM:
		err = prepareEVM(tx, address, &req)
	case TON:
		err = preparePayload(tx, "payload_base64", TONCell, &req)
	case TRON:
		err = preparePayload(tx, "raw_data_hex", TRONRawData, &req)
	case XRP, XRPTestnet:
		err = preparePayload(tx, "tx_blob_hex", XRPBlob, &req)
	case Solana:
		err = preparePayload(tx, "message_base64", SolanaMessage, &req)
	case BTC, BTCTestnet, LTC, LTCTestnet, BCH, BCHTestnet, DOGE, DOGETestnet:
		err = prepareUTXO(tx, &req)
	default:
		return zero, ErrUnsupported
	}
	if err != nil {
		return zero, err
	}
	if err := ValidateRequest(req); err != nil {
		return zero, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	out := SigningRequest{Request: req, Address: address}
	if rawContext := fields["inspection_context"]; rawContext != nil {
		out.InspectionContext, err = decodeSourceContext(rawContext)
		if err != nil {
			return zero, err
		}
	}
	return out, nil
}

// Inspect checks that the callback names the independently selected wallet
// before inspecting its signed instructions. For a Solana token payment, set
// InspectionContext.TokenMint and RecipientOwner from the merchant's own order.
func (r SigningRequest) Inspect(wallet Wallet) (Inspection, error) {
	if wallet.Family != r.Request.Family || !sameSigningAddress(r.Request.Family, r.Address, wallet.Address) {
		return Inspection{}, ErrSender
	}
	return InspectTransfer(r.Request, wallet, r.InspectionContext)
}

func sameSigningAddress(family Family, actual, registered string) bool {
	if family == EVM {
		return common.IsHexAddress(actual) && common.IsHexAddress(registered) &&
			common.HexToAddress(actual) == common.HexToAddress(registered)
	}
	return actual != "" && actual == registered
}

type processingFields map[string]json.RawMessage

func readProcessingObject(raw []byte, allowed ...string) (processingFields, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := d.Token(); err != nil || tok != json.Delim('{') {
		return nil, ErrMalformed
	}
	f := make(processingFields, len(allowed))
	for d.More() {
		tok, err := d.Token()
		name, ok := tok.(string)
		if err != nil || !ok || !slices.Contains(allowed, name) || f[name] != nil {
			return nil, ErrMalformed
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return nil, ErrMalformed
		}
		f[name] = value
	}
	if tok, err := d.Token(); err != nil || tok != json.Delim('}') {
		return nil, ErrMalformed
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrMalformed
	}
	return f, nil
}

func (f processingFields) str(name string) (string, error) {
	var s string
	if err := json.Unmarshal(f[name], &s); err != nil {
		return "", fmt.Errorf("%w: invalid or missing %s", ErrMalformed, name)
	}
	return s, nil
}

func (f processingFields) hexBytes(name string) ([]byte, error) {
	s, err := f.str(name)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s", ErrMalformed, name)
	}
	return b, nil
}

// Merchant expectations such as recipient_owner and token_mint must be
// independent of CryptoChief. The callback can only supply source data.
func decodeSourceContext(raw []byte) (InspectionContext, error) {
	var ctx InspectionContext
	f, err := readProcessingObject(raw, "source_payload_hex", "input_index", "previous_transactions")
	if err != nil {
		return ctx, err
	}
	if f["input_index"] != nil {
		if err := json.Unmarshal(f["input_index"], &ctx.InputIndex); err != nil {
			return InspectionContext{}, ErrContext
		}
	}
	if f["source_payload_hex"] != nil {
		ctx.PayloadHex, err = f.str("source_payload_hex")
		if err != nil || !validSourceHex(ctx.PayloadHex) {
			return InspectionContext{}, ErrContext
		}
	}
	if previous := f["previous_transactions"]; previous != nil {
		d := json.NewDecoder(bytes.NewReader(previous))
		if first, err := d.Token(); err != nil || first != json.Delim('[') || !d.More() {
			return InspectionContext{}, ErrContext
		}
		total := 0
		for d.More() {
			var tx string
			if d.Decode(&tx) != nil || !validSourceHex(tx) {
				return InspectionContext{}, ErrContext
			}
			total += len(tx)
			// A serialized input occupies at least 41 bytes of the source.
			if total > 2*MaxBatchPayloadBytes || len(ctx.PreviousTransactions) >= MaxPayloadBytes/41 {
				return InspectionContext{}, ErrContext
			}
			ctx.PreviousTransactions = append(ctx.PreviousTransactions, tx)
		}
	}
	return ctx, nil
}

func validSourceHex(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 || len(s) > 2*MaxPayloadBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func preparePayload(raw []byte, source string, kind PayloadType, req *Request) error {
	f, err := readProcessingObject(raw, source, "digest_hex")
	if err != nil {
		return err
	}
	if len(f) != 1 {
		return ErrMalformed
	}
	if f["digest_hex"] != nil {
		if req.Family == Solana {
			// Ed25519 signs the compiled message itself on Solana.
			return ErrUnsupported
		}
		source, kind = "digest_hex", Digest
	}
	var payload []byte
	if kind == TONCell || kind == SolanaMessage {
		s, err := f.str(source)
		if err != nil {
			return err
		}
		payload, err = base64.StdEncoding.Strict().DecodeString(s)
		if err != nil || strings.ContainsAny(s, "\r\n") {
			return fmt.Errorf("%w: invalid %s", ErrMalformed, source)
		}
	} else {
		payload, err = f.hexBytes(source)
		if err != nil {
			return err
		}
	}
	req.PayloadType, req.PayloadHex = kind, hex.EncodeToString(payload)
	return nil
}

func prepareUTXO(raw []byte, req *Request) error {
	f, err := readProcessingObject(raw, "sighash_hex", "hash_type")
	if err != nil {
		return err
	}
	b, err := f.hexBytes("sighash_hex")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(f["hash_type"], &req.HashType); err != nil {
		return fmt.Errorf("%w: invalid hash_type", ErrMalformed)
	}
	req.PayloadType, req.PayloadHex = Digest, hex.EncodeToString(b)
	return nil
}

func (f processingFields) quantity(name string, bits int) (*big.Int, error) {
	s, err := f.str(name)
	if err != nil {
		return nil, err
	}
	base := 10
	if strings.HasPrefix(s, "0x") {
		s, base = s[2:], 16
	}
	// Bound parsing work before converting an untrusted integer. Even in
	// decimal an unsigned 256-bit value has at most 78 digits.
	if len(s) == 0 || len(s) > 78 || s[0] == '+' || s[0] == '-' {
		return nil, fmt.Errorf("%w: invalid %s", ErrMalformed, name)
	}
	n, ok := new(big.Int).SetString(s, base)
	if !ok || n.BitLen() > bits {
		return nil, fmt.Errorf("%w: invalid %s", ErrMalformed, name)
	}
	return n, nil
}

func prepareEVM(raw []byte, registered string, req *Request) error {
	f, err := readProcessingObject(raw, "chain_id", "nonce", "from", "to", "value", "gas", "data",
		"gas_price", "max_fee_per_gas", "max_priority_fee_per_gas")
	if err != nil {
		return err
	}
	if f["from"] != nil {
		from, err := f.str("from")
		if err != nil {
			return err
		}
		if !sameSigningAddress(EVM, from, registered) {
			return ErrSender
		}
	}
	dest, err := f.str("to")
	if err != nil || !common.IsHexAddress(dest) {
		return fmt.Errorf("%w: invalid to", ErrMalformed)
	}
	to := common.HexToAddress(dest)
	chain, err := f.quantity("chain_id", 256)
	if err != nil || chain.Sign() == 0 {
		return fmt.Errorf("%w: invalid chain_id", ErrMalformed)
	}
	nonce, err := f.quantity("nonce", 64)
	if err != nil {
		return err
	}
	gas, err := f.quantity("gas", 64)
	if err != nil {
		return err
	}
	value, err := f.quantity("value", 256)
	if err != nil {
		return err
	}
	data, err := f.hexBytes("data")
	if err != nil {
		return err
	}
	var tx *types.Transaction
	if f["gas_price"] != nil {
		if f["max_fee_per_gas"] != nil || f["max_priority_fee_per_gas"] != nil {
			return fmt.Errorf("%w: conflicting EVM fees", ErrMalformed)
		}
		price, err := f.quantity("gas_price", 256)
		if err != nil {
			return err
		}
		tx = types.NewTx(&types.LegacyTx{Nonce: nonce.Uint64(), GasPrice: price,
			Gas: gas.Uint64(), To: &to, Value: value, Data: data})
	} else {
		cap, err := f.quantity("max_fee_per_gas", 256)
		if err != nil {
			return err
		}
		tip, err := f.quantity("max_priority_fee_per_gas", 256)
		if err != nil || tip.Cmp(cap) > 0 {
			return fmt.Errorf("%w: invalid max_priority_fee_per_gas", ErrMalformed)
		}
		tx = types.NewTx(&types.DynamicFeeTx{ChainID: chain, Nonce: nonce.Uint64(),
			GasTipCap: tip, GasFeeCap: cap, Gas: gas.Uint64(), To: &to, Value: value, Data: data})
	}
	b, err := tx.MarshalBinary()
	if err != nil {
		return fmt.Errorf("%w: cannot encode EVM transaction", ErrMalformed)
	}
	req.PayloadType, req.PayloadHex, req.ChainID = EVMTransaction, hex.EncodeToString(b), chain.String()
	return nil
}
