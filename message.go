package signer

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/crypto"
)

const (
	TRONPrefixV2        = "v2"
	TRONPrefixLegacy32  = "legacy32"
	MaxTRONMessageBytes = 512
)

// TRONMessageDigest applies the same TIP-191 domain separation as Crypto Chief's
// TRON message signer. The message is literal UTF-8: hex-looking strings are not
// decoded or trimmed. prefixMode must be explicit; an empty or unknown mode fails.
func TRONMessageDigest(message, prefixMode string) ([32]byte, error) {
	var digest [32]byte
	if !utf8.ValidString(message) {
		return digest, errors.New("TRON message must be valid UTF-8")
	}
	if strings.TrimSpace(message) == "" {
		return digest, errors.New("TRON message is required")
	}
	if len(message) > MaxTRONMessageBytes {
		return digest, errors.New("TRON message exceeds the 512-byte limit")
	}
	for _, r := range message {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if !unicode.IsPrint(r) {
			return digest, errors.New("TRON message contains a non-printable character")
		}
	}
	length := "32"
	switch prefixMode {
	case TRONPrefixV2:
		length = strconv.Itoa(len(message))
	case TRONPrefixLegacy32:
	default:
		return digest, errors.New("TRON prefix_mode must be v2 or legacy32")
	}
	copy(digest[:], crypto.Keccak256([]byte("\x19TRON Signed Message:\n"+length), []byte(message)))
	return digest, nil
}

// SignTRONMessage signs a readable TIP-191 message locally, using the existing
// secp256k1 signing path. The caller must separately approve operation_type=message
// and bind the exact message AND prefixMode in its authorization envelope.
// The returned recovery byte is 0/1, as for Sign, rather than TronLink's 27/28.
func SignTRONMessage(message, prefixMode string, privateKey []byte) (Signature, error) {
	digest, err := TRONMessageDigest(message, prefixMode)
	if err != nil {
		return Signature{}, err
	}
	return Sign(Request{
		Version:     1,
		Family:      TRON,
		PayloadType: Digest,
		PayloadHex:  hex.EncodeToString(digest[:]),
	}, privateKey)
}
