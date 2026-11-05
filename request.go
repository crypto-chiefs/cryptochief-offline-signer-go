package signer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// MaxRequestJSONBytes bounds the JSON transport representation, including metadata.
const MaxRequestJSONBytes = 2*MaxPayloadBytes + 4096

// DecodeRequest is the strict decoder for untrusted SDK request JSON. It rejects
// unknown, duplicate (including escaped equivalents), null and missing fields,
// case variants of field names and extra JSON values. It does not authorize signing.
func DecodeRequest(raw []byte) (Request, error) {
	var req Request
	if len(raw) == 0 || len(raw) > MaxRequestJSONBytes || !utf8.Valid(raw) {
		return req, errors.New("invalid request JSON size or encoding")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return req, errors.New("request must be a JSON object")
	}
	seen := make(map[string]bool, 7)
	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return Request{}, errors.New("invalid request field")
		}
		name, ok := tok.(string)
		if !ok || seen[name] {
			return Request{}, errors.New("duplicate or invalid request field")
		}
		seen[name] = true
		var target any
		switch name {
		case "version":
			target = &req.Version
		case "chain_family":
			target = &req.Family
		case "payload_type":
			target = &req.PayloadType
		case "payload_hex":
			target = &req.PayloadHex
		case "chain_id":
			target = &req.ChainID
		case "hash_type":
			target = &req.HashType
		default:
			return Request{}, errors.New("unknown request field")
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return Request{}, errors.New("invalid or null request value")
		}
		if json.Unmarshal(value, target) != nil {
			return Request{}, errors.New("invalid request value type")
		}
	}
	if tok, err = dec.Token(); err != nil || tok != json.Delim('}') {
		return Request{}, errors.New("invalid request object")
	}
	if _, err = dec.Token(); err != io.EOF {
		return Request{}, errors.New("trailing request data")
	}
	for _, field := range []string{"version", "chain_family", "payload_type", "payload_hex"} {
		if !seen[field] {
			return Request{}, errors.New("missing required request field")
		}
	}
	if err = ValidateRequest(req); err != nil {
		return Request{}, err
	}
	return req, nil
}

// CanonicalRequest returns the exact v1 JSON representation for the SDK payload
// inside the merchant's approval envelope. Field order follows Request; absent
// chain_id/hash_type equal empty/zero, and strings retain their original spelling.
// No network, key lookup, authorization, timestamps or replay checks occur here.
func CanonicalRequest(req Request) ([]byte, error) {
	if err := ValidateRequest(req); err != nil {
		return nil, err
	}
	return json.Marshal(req)
}

// RequestDigest hashes the COMPLETE canonical SDK request, including family,
// payload type, EVM chain ID and UTXO hash type. It is distinct from the blockchain
// signing digest returned in Signature.DigestHex, and does not replace binding
// project/key/request ID/network/operation/expiry in the merchant approval envelope.
func RequestDigest(req Request) (string, error) {
	b, err := CanonicalRequest(req)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
