package signer

import (
	"encoding/binary"
	"math"
	"strconv"
	"unicode/utf8"
)

// The small set of accepted fields is taken from protocol.Transaction.raw,
// Contract, Any, TransferContract and TriggerSmartContract in tronprotocol/protocol.
// A duplicate or an unknown field cannot silently change an inspected payment.
type tronField struct {
	integer uint64
	data    []byte
}
type tronMessage map[int]tronField

func tronFields(raw []byte, schema map[int]byte) (tronMessage, error) {
	fields := make(tronMessage, len(schema))
	for len(raw) > 0 {
		tag, n := binary.Uvarint(raw)
		if n <= 0 || tag>>3 == 0 || tag>>3 > 1<<29-1 {
			return nil, ErrMalformed
		}
		raw = raw[n:]
		num := int(tag >> 3)
		if _, dup := fields[num]; dup {
			return nil, ErrUnsupported
		}
		wire, ok := schema[num]
		if !ok || uint64(wire) != tag&7 {
			return nil, ErrUnsupported
		}
		v, n := binary.Uvarint(raw)
		if n <= 0 {
			return nil, ErrMalformed
		}
		raw = raw[n:]
		f := tronField{integer: v}
		if wire == 2 {
			if v > uint64(len(raw)) {
				return nil, ErrMalformed
			}
			f.data, raw = raw[:v], raw[v:]
		}
		fields[num] = f
	}
	return fields, nil
}

func tronAddress(b []byte) (string, error) {
	if len(b) != 21 || b[0] != 0x41 {
		return "", ErrMalformed
	}
	return walletBase58Check(0x41, b[1:], bitcoinAlphabet), nil
}

func inspectTRON(raw []byte, wallet Wallet) ([]Transfer, error) {
	m, err := tronFields(raw, map[int]byte{1: 2, 3: 0, 4: 2, 8: 0, 10: 2, 11: 2, 14: 0, 18: 0})
	if err != nil {
		return nil, err
	}
	c, err := tronFields(m[11].data, map[int]byte{1: 0, 2: 2, 5: 0})
	if err != nil {
		return nil, err
	}
	if c[5].integer != 0 {
		return nil, ErrUnsupported
	}
	param, err := tronFields(c[2].data, map[int]byte{1: 2, 2: 2})
	if err != nil {
		return nil, err
	}
	var body tronMessage
	t := Transfer{Asset: Asset{Kind: "native"}}
	switch c[1].integer {
	case 1:
		if string(param[1].data) != "type.googleapis.com/protocol.TransferContract" {
			return nil, ErrMalformed
		}
		body, err = tronFields(param[2].data, map[int]byte{1: 2, 2: 2, 3: 0})
		if err != nil {
			return nil, err
		}
		if body[3].integer == 0 || body[3].integer > math.MaxInt64 {
			return nil, ErrMalformed
		}
		t.To, err = tronAddress(body[2].data)
		t.AmountAtomic = strconv.FormatUint(body[3].integer, 10)
	case 31:
		if string(param[1].data) != "type.googleapis.com/protocol.TriggerSmartContract" {
			return nil, ErrMalformed
		}
		body, err = tronFields(param[2].data, map[int]byte{1: 2, 2: 2, 3: 0, 4: 2, 5: 0, 6: 0})
		if err != nil {
			return nil, err
		}
		if body[3].integer != 0 || body[5].integer != 0 || body[6].integer != 0 {
			return nil, ErrUnsupported
		}
		var to []byte
		to, t.AmountAtomic, err = decodeTokenTransfer(body[4].data)
		if err != nil {
			return nil, err
		}
		t.To = walletBase58Check(0x41, to, bitcoinAlphabet)
		t.Asset.Kind = "token"
		t.Asset.Contract, err = tronAddress(body[2].data)
	default:
		return nil, ErrUnsupported
	}
	if err != nil {
		return nil, err
	}
	t.From, err = tronAddress(body[1].data)
	if err != nil {
		return nil, err
	}
	id, err := accountID(wallet.PublicKeyHex)
	if err != nil || t.From != wallet.Address || walletBase58Check(0x41, id.Bytes(), bitcoinAlphabet) != t.From {
		return nil, ErrSender
	}
	if !utf8.Valid(m[10].data) || m[18].integer > math.MaxInt64 {
		return nil, ErrUnsupported
	}
	t.Memo = string(m[10].data)
	if _, ok := m[18]; ok {
		t.FeeLimitAtomic = strconv.FormatUint(m[18].integer, 10)
	}
	return []Transfer{t}, nil
}
