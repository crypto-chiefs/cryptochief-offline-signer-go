package signer

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

// The transaction service serializes a single-signing Payment without the STX
// prefix. Unknown fields can change what a Payment spends, so only the direct
// payment fields below are accepted, in XRPL canonical field order.
func inspectXRP(_ Request, payload []byte, wallet Wallet, _ InspectionContext) ([]Transfer, error) {
	r := bytes.NewReader(payload)
	var result Transfer
	var account, publicKey []byte
	var payment, sequence, haveFee bool
	last := 0
	for r.Len() > 0 {
		header, _ := r.ReadByte()
		typ, field := int(header>>4), int(header&15)
		if field == 0 {
			n, err := r.ReadByte()
			if err != nil || n < 16 {
				return nil, ErrMalformed
			}
			field = int(n)
		}
		if typ == 0 {
			return nil, ErrUnsupported
		}
		tag := typ<<8 | field
		if tag <= last {
			return nil, ErrMalformed
		}
		last = tag
		switch tag {
		case 0x102: // TransactionType
			b, err := xrpRead(r, 2)
			if err != nil {
				return nil, err
			}
			if binary.BigEndian.Uint16(b) != 0 {
				return nil, ErrUnsupported
			}
			payment = true
		case 0x202, 0x204, 0x20e, 0x21b: // Flags, Sequence, DestinationTag, LastLedgerSequence
			b, err := xrpRead(r, 4)
			if err != nil {
				return nil, err
			}
			n := binary.BigEndian.Uint32(b)
			switch tag {
			case 0x202:
				if n&^uint32(0x80000000) != 0 {
					return nil, ErrUnsupported
				}
			case 0x204:
				if n == 0 {
					return nil, ErrUnsupported
				} // ticket-based transactions
				sequence = true
			case 0x20e:
				result.DestinationTag = &n
			}
		case 0x601, 0x608: // Amount, Fee
			b, err := xrpRead(r, 8)
			if err != nil {
				return nil, err
			}
			bits := binary.BigEndian.Uint64(b)
			if bits>>63 == 0 {
				if bits>>61 != 2 {
					return nil, ErrUnsupported
				} // negative or MPT
				n := bits & ((uint64(1) << 61) - 1)
				if n > 100_000_000_000_000_000 {
					return nil, ErrMalformed
				}
				if tag == 0x608 {
					result.FeeAtomic = strconv.FormatUint(n, 10)
					haveFee = true
				} else {
					if n == 0 {
						return nil, ErrUnsupported
					}
					result.AmountAtomic = strconv.FormatUint(n, 10)
					result.Asset = Asset{Kind: "native"}
				}
			} else {
				if tag == 0x608 {
					return nil, ErrMalformed
				}
				result.AmountDecimal, result.Asset, err = xrpIssuedAmount(r, bits)
				if err != nil {
					return nil, err
				}
			}
		case 0x703: // SigningPubKey, compressed secp256k1, checked against the selected account
			var err error
			publicKey, err = xrpSized(r, 33)
			if err != nil {
				return nil, err
			}
			if publicKey[0] != 2 && publicKey[0] != 3 {
				return nil, ErrUnsupported
			}
		case 0x801, 0x803: // Account, Destination
			id, err := xrpSized(r, 20)
			if err != nil {
				return nil, err
			}
			if !xrpAccount(id) {
				return nil, ErrMalformed
			}
			addr := walletBase58Check(0, id, rippleAlphabet)
			if tag == 0x801 {
				account = id
				result.From = addr
			} else {
				result.To = addr
			}
		default:
			return nil, ErrUnsupported
		}
	}
	if !payment || !sequence || !haveFee || result.Asset.Kind == "" || result.To == "" || account == nil || publicKey == nil {
		return nil, ErrMalformed
	}
	expected, err := hex.DecodeString(wallet.PublicKeyHex)
	if err != nil || !bytes.Equal(publicKey, expected) || !bytes.Equal(account, walletHash160(publicKey)) || result.From != wallet.Address {
		return nil, ErrSender
	}
	// Amount.issuer equal to Destination permits any issuer it accepts. The
	// signed bytes would not identify a unique asset for the recipient.
	if result.From == result.To || result.Asset.Issuer == result.To {
		return nil, ErrUnsupported
	}
	return []Transfer{result}, nil
}

func xrpRead(r *bytes.Reader, n int) ([]byte, error) {
	if n > r.Len() {
		return nil, ErrMalformed
	}
	b := make([]byte, n)
	_, _ = r.Read(b)
	return b, nil
}

func xrpSized(r *bytes.Reader, n int) ([]byte, error) {
	length, err := r.ReadByte()
	if err != nil || int(length) != n {
		return nil, ErrMalformed
	}
	return xrpRead(r, n)
}

func xrpAccount(b []byte) bool {
	return !bytes.Equal(b[:19], make([]byte, 19)) || b[19] > 1
}

func xrpIssuedAmount(r *bytes.Reader, bits uint64) (string, Asset, error) {
	const sign = uint64(1) << 62
	exp := int((bits>>54)&255) - 97
	mantissa := bits & ((uint64(1) << 54) - 1)
	if bits&sign == 0 || mantissa < 1_000_000_000_000_000 || mantissa > 9_999_999_999_999_999 || exp < -96 || exp > 80 {
		return "", Asset{}, ErrMalformed
	}
	code, err := xrpRead(r, 20)
	if err != nil {
		return "", Asset{}, err
	}
	currency := strings.ToUpper(hex.EncodeToString(code))
	if code[0] == 0 {
		if !bytes.Equal(code[:12], make([]byte, 12)) || !bytes.Equal(code[15:], make([]byte, 5)) {
			return "", Asset{}, ErrMalformed
		}
		currency = string(code[12:15])
		const valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?!@#$%^&*<>(){}[]|"
		if currency == "XRP" || strings.IndexFunc(currency, func(ch rune) bool { return !strings.ContainsRune(valid, ch) }) >= 0 {
			return "", Asset{}, ErrMalformed
		}
	}
	issuer, err := xrpRead(r, 20)
	if err != nil || !xrpAccount(issuer) {
		return "", Asset{}, ErrMalformed
	}
	digits := strconv.FormatUint(mantissa, 10)
	if exp >= 0 {
		digits += strings.Repeat("0", exp)
	} else {
		point := len(digits) + exp
		if point <= 0 {
			digits = "0." + strings.Repeat("0", -point) + digits
		} else {
			digits = digits[:point] + "." + digits[point:]
		}
		digits = strings.TrimSuffix(strings.TrimRight(digits, "0"), ".")
	}
	return digits, Asset{Kind: "issued", Currency: currency, Issuer: walletBase58Check(0, issuer, rippleAlphabet)}, nil
}
