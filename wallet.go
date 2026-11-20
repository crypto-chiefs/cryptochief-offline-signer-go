package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"golang.org/x/crypto/ripemd160"
)

// WalletOptions selects the service-compatible address scheme. Family aliases
// select UTXO testnets. TONTestnet sets the address's test-only flag; it does not
// change the V4R2 account ID. Zero TON flags match the current wallet service.
// Wallet role (master/transit/static), project and network are caller metadata.
type WalletOptions struct {
	Family           Family `json:"chain_family"`
	TONTestnet       bool   `json:"ton_testnet,omitempty"`
	TONNonBounceable bool   `json:"ton_non_bounceable,omitempty"`
}

// Wallet contains public data only and is safe to use as a registration record.
// Secp256k1 public keys use the same compressed 33-byte encoding as Sign;
// Ed25519 public keys are 32 bytes. TON uses V4R2, workchain 0, subwallet 698983191.
type Wallet struct {
	Family         Family `json:"chain_family"`
	Address        string `json:"address"`
	PublicKeyHex   string `json:"public_key_hex"`
	AddressType    string `json:"address_type"`
	TONSubwalletID uint32 `json:"ton_subwallet_id,omitempty"`
}

// GenerateWallet creates a key using the operating system CSPRNG and derives its
// public record. The separate secret result is always 32 raw bytes (Ed25519 seed
// or secp256k1 scalar). It is never stored or logged. The caller must securely store
// it and clear its buffer after use; Go does not guarantee removal of all copies.
func GenerateWallet(options WalletOptions) (Wallet, []byte, error) {
	if err := validateWalletOptions(options); err != nil {
		return Wallet{}, nil, err
	}
	var secret []byte
	if options.Family == TON || options.Family == Solana {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			clear(secret)
			return Wallet{}, nil, errors.New("wallet entropy unavailable")
		}
	} else {
		key, err := crypto.GenerateKey()
		if err != nil {
			return Wallet{}, nil, errors.New("wallet entropy unavailable")
		}
		secret = crypto.FromECDSA(key)
		clear(key.D.Bits())
		key.D.SetInt64(0)
	}
	wallet, err := DeriveWallet(options, secret)
	if err != nil {
		clear(secret)
		return Wallet{}, nil, err
	}
	return wallet, secret, nil
}

// DeriveWallet reconstructs public data locally to verify a decrypted key against
// the merchant's wallet registry. It neither modifies nor retains privateKey.
func DeriveWallet(options WalletOptions, privateKey []byte) (Wallet, error) {
	if err := validateWalletOptions(options); err != nil {
		return Wallet{}, err
	}
	w := Wallet{Family: options.Family}
	if options.Family == TON || options.Family == Solana {
		key, err := edKey(privateKey)
		if err != nil {
			return Wallet{}, err
		}
		defer clear(key)
		pub := key.Public().(ed25519.PublicKey)
		w.PublicKeyHex = hex.EncodeToString(pub)
		if options.Family == Solana {
			w.Address = walletBase58(pub, bitcoinAlphabet)
			w.AddressType = "ed25519"
		} else {
			w.Address, err = tonWalletAddress(pub, options)
			if err != nil {
				return Wallet{}, err
			}
			w.AddressType = "v4r2"
			w.TONSubwalletID = 698983191
		}
		return w, nil
	}
	key, err := crypto.ToECDSA(privateKey)
	if err != nil {
		return Wallet{}, errors.New("invalid secp256k1 private key: expected a valid 32-byte scalar")
	}
	defer func() { clear(key.D.Bits()); key.D.SetInt64(0) }()
	pub := crypto.CompressPubkey(&key.PublicKey)
	w.PublicKeyHex = hex.EncodeToString(pub)
	hash := walletHash160(pub)
	switch options.Family {
	case EVM:
		w.Address = crypto.PubkeyToAddress(key.PublicKey).Hex()
		w.AddressType = "eip55"
	case TRON:
		w.Address = walletBase58Check(0x41, crypto.PubkeyToAddress(key.PublicKey).Bytes(), bitcoinAlphabet)
		w.AddressType = "base58check"
	case XRP, XRPTestnet:
		w.Address = walletBase58Check(0, hash, rippleAlphabet)
		w.AddressType = "classic"
	case BTC, BTCTestnet, LTC, LTCTestnet:
		hrp := map[Family]string{BTC: "bc", BTCTestnet: "tb", LTC: "ltc", LTCTestnet: "tltc"}[options.Family]
		w.Address = walletWitnessAddress(hrp, hash)
		w.AddressType = "p2wpkh"
	case DOGE, DOGETestnet:
		version := byte(0x1e)
		if options.Family == DOGETestnet {
			version = 0x71
		}
		w.Address = walletBase58Check(version, hash, bitcoinAlphabet)
		w.AddressType = "p2pkh"
	case BCH, BCHTestnet:
		prefix := "bitcoincash"
		if options.Family == BCHTestnet {
			prefix = "bchtest"
		}
		w.Address = walletCashAddress(prefix, hash)
		w.AddressType = "cashaddr-p2pkh"
	}
	return w, nil
}

func validateWalletOptions(o WalletOptions) error {
	if o.Family != TON && (o.TONTestnet || o.TONNonBounceable) {
		return errors.New("TON address flags are only valid for TON")
	}
	switch o.Family {
	case EVM, TRON, TON, Solana, XRP, XRPTestnet, BTC, BTCTestnet, LTC, LTCTestnet, BCH, BCHTestnet, DOGE, DOGETestnet:
		return nil
	default:
		return errors.New("unsupported wallet family")
	}
}

func tonWalletAddress(pub []byte, o WalletOptions) (string, error) {
	b, err := hex.DecodeString(tonV4R2CodeHex)
	if err != nil {
		return "", errors.New("invalid embedded TON wallet code")
	}
	code, err := cell.FromBOC(b)
	if err != nil {
		return "", errors.New("invalid embedded TON wallet code")
	}
	// Matches tonutils-go v1.15.5 wallet.GetStateInit(V4R2, DefaultSubwallet).
	data := cell.BeginCell().MustStoreUInt(0, 32).MustStoreUInt(698983191, 32).
		MustStoreSlice(pub, 256).MustStoreDict(nil).EndCell()
	// StateInit: absent split_depth/special, present code/data, empty library.
	state := cell.BeginCell().MustStoreUInt(0, 2).MustStoreBoolBit(true).MustStoreRef(code).
		MustStoreBoolBit(true).MustStoreRef(data).MustStoreBoolBit(false).EndCell()
	a := address.NewAddress(0, 0, state.Hash())
	a.SetBounce(!o.TONNonBounceable)
	a.SetTestnetOnly(o.TONTestnet)
	return a.String(), nil
}

const bitcoinAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
const rippleAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
const walletBase32Alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func walletHash160(b []byte) []byte {
	s := sha256.Sum256(b)
	h := ripemd160.New()
	h.Write(s[:])
	return h.Sum(nil)
}

func walletBase58Check(version byte, payload []byte, alphabet string) string {
	b := append([]byte{version}, payload...)
	h := sha256.Sum256(b)
	h = sha256.Sum256(h[:])
	return walletBase58(append(b, h[:4]...), alphabet)
}

// Address encoders operate only on public bytes.
func walletBase58(b []byte, alphabet string) string {
	n := new(big.Int).SetBytes(b)
	base := big.NewInt(58)
	var rem big.Int
	var out []byte
	for n.Sign() > 0 {
		n.QuoRem(n, base, &rem)
		out = append(out, alphabet[rem.Int64()])
	}
	for _, v := range b {
		if v != 0 {
			break
		}
		out = append(out, alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func walletToFiveBits(b []byte) []byte {
	var acc uint32
	var bits uint
	out := make([]byte, 0, (len(b)*8+4)/5)
	for _, v := range b {
		acc = (acc << 8) | uint32(v)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, byte((acc>>bits)&31))
		}
	}
	if bits > 0 {
		out = append(out, byte((acc<<(5-bits))&31))
	}
	return out
}

func walletWitnessAddress(hrp string, hash []byte) string {
	return encodeWitnessProgram(hrp, 0, hash)
}

func encodeWitnessProgram(hrp string, version byte, program []byte) string {
	data := append([]byte{version}, walletToFiveBits(program)...)
	var expanded []byte
	for _, v := range []byte(hrp) {
		expanded = append(expanded, v>>5)
	}
	expanded = append(expanded, 0)
	for _, v := range []byte(hrp) {
		expanded = append(expanded, v&31)
	}
	expanded = append(expanded, data...)
	expanded = append(expanded, make([]byte, 6)...)
	var polymod uint32 = 1
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	for _, v := range expanded {
		top := polymod >> 25
		polymod = ((polymod & 0x1ffffff) << 5) ^ uint32(v)
		for i, g := range gen {
			if (top>>i)&1 != 0 {
				polymod ^= g
			}
		}
	}
	if version == 0 {
		polymod ^= 1
	} else {
		polymod ^= 0x2bc830a3 // Bech32m for witness versions 1 through 16
	}
	for i := 0; i < 6; i++ {
		data = append(data, byte((polymod>>uint(5*(5-i)))&31))
	}
	var s strings.Builder
	s.WriteString(hrp)
	s.WriteByte('1')
	for _, v := range data {
		s.WriteByte(walletBase32Alphabet[v])
	}
	return s.String()
}

// Port of wallet-service btc.go's CashAddr P2PKH encoder.
func walletCashAddress(prefix string, hash []byte) string {
	return encodeCashAddress(prefix, 0, hash)
}

func encodeCashAddress(prefix string, version byte, hash []byte) string {
	data := walletToFiveBits(append([]byte{version}, hash...))
	var expanded []byte
	for _, v := range []byte(prefix) {
		expanded = append(expanded, v&31)
	}
	expanded = append(expanded, 0)
	expanded = append(expanded, data...)
	expanded = append(expanded, make([]byte, 8)...)
	var polymod uint64 = 1
	gen := [5]uint64{0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470}
	for _, v := range expanded {
		top := polymod >> 35
		polymod = ((polymod & 0x07ffffffff) << 5) ^ uint64(v)
		for i, g := range gen {
			if (top>>i)&1 != 0 {
				polymod ^= g
			}
		}
	}
	polymod ^= 1
	for i := 0; i < 8; i++ {
		data = append(data, byte((polymod>>uint(5*(7-i)))&31))
	}
	var s strings.Builder
	s.WriteString(prefix)
	s.WriteByte(':')
	for _, v := range data {
		s.WriteByte(walletBase32Alphabet[v])
	}
	return s.String()
}
