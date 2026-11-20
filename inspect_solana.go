package signer

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strconv"
	"strings"

	"filippo.io/edwards25519"
)

const (
	solSystemProgram = "11111111111111111111111111111111"
	solTokenProgram  = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	solATAProgram    = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
	solBudgetProgram = "ComputeBudget111111111111111111111111111111"
)

type solKey [32]byte

func (k solKey) address() string { return walletBase58(k[:], bitcoinAlphabet) }

func solParseAddress(s string) (solKey, error) {
	var key solKey
	if len(s) < 32 || len(s) > 44 {
		return key, ErrContext
	}
	var n big.Int
	for i := 0; i < len(s); i++ {
		d := strings.IndexByte(bitcoinAlphabet, s[i])
		if d < 0 {
			return key, ErrContext
		}
		n.Mul(&n, big.NewInt(58))
		n.Add(&n, big.NewInt(int64(d)))
	}
	if n.BitLen() > 256 {
		return key, ErrContext
	}
	n.FillBytes(key[:])
	if key.address() != s {
		return key, ErrContext
	}
	return key, nil
}

// SPL associated accounts are PDAs of [owner, Token program, mint]. The bump
// and the point check are part of the address and must match the on-chain program.
func solATA(owner, mint solKey) (solKey, error) {
	token, _ := solParseAddress(solTokenProgram)
	program, _ := solParseAddress(solATAProgram)
	for bump := 255; bump > 0; bump-- {
		h := sha256.New()
		h.Write(owner[:])
		h.Write(token[:])
		h.Write(mint[:])
		h.Write([]byte{byte(bump)})
		h.Write(program[:])
		h.Write([]byte("ProgramDerivedAddress"))
		var k solKey
		copy(k[:], h.Sum(nil))
		if _, err := new(edwards25519.Point).SetBytes(k[:]); err != nil {
			return k, nil
		}
	}
	return solKey{}, ErrUnsupported
}

type solCursor struct{ data []byte }

func (r *solCursor) take(n int) ([]byte, error) {
	if n > len(r.data) {
		return nil, ErrMalformed
	}
	b := r.data[:n]
	r.data = r.data[n:]
	return b, nil
}
func (r *solCursor) length() (int, error) {
	var n int
	for i := 0; i < 3; i++ {
		b, err := r.take(1)
		if err != nil {
			return 0, err
		}
		v := b[0]
		if (i == 2 && v > 3) || (i > 0 && v == 0) {
			return 0, ErrMalformed
		}
		n |= int(v&127) << (7 * i)
		if v < 128 {
			return n, nil
		}
	}
	return 0, ErrMalformed
}

type solInstruction struct {
	program  string
	accounts []byte
	data     []byte
}
type solMessage struct {
	keys     []solKey
	writable int
	ix       []solInstruction
}

func solReadMessage(b []byte) (solMessage, error) {
	var m solMessage
	// The packet includes a one-byte signature count and one 64-byte signature.
	if len(b) == 0 || len(b) > 1232-65 {
		return m, ErrMalformed
	}
	r := solCursor{b}
	versioned := b[0]&0x80 != 0
	if versioned {
		if b[0] != 0x80 {
			return m, ErrUnsupported
		}
		r.data = r.data[1:]
	}
	header, err := r.take(3)
	if err != nil {
		return m, err
	}
	if header[0] != 1 || header[1] != 0 {
		return m, ErrUnsupported
	}
	n, err := r.length()
	if err != nil || n < 2 || n > 256 || int(header[2]) >= n {
		return m, ErrMalformed
	}
	m.writable = n - int(header[2])
	seen := make(map[solKey]bool, n)
	for i := 0; i < n; i++ {
		raw, err := r.take(32)
		if err != nil {
			return m, err
		}
		key := solKey(raw)
		if seen[key] {
			return m, ErrMalformed
		}
		seen[key] = true
		m.keys = append(m.keys, key)
	}
	if _, err := r.take(32); err != nil {
		return m, err
	} // recent blockhash
	count, err := r.length()
	if err != nil {
		return m, err
	}
	if count < 1 || count > 4 {
		return m, ErrUnsupported
	}
	for i := 0; i < count; i++ {
		p, err := r.take(1)
		if err != nil {
			return m, err
		}
		if int(p[0]) >= n {
			return m, ErrUnsupported
		} // external address table
		if int(p[0]) < m.writable {
			return m, ErrUnsupported
		}
		k, err := r.length()
		if err != nil {
			return m, err
		}
		accounts, err := r.take(k)
		if err != nil {
			return m, err
		}
		for _, a := range accounts {
			if int(a) >= n {
				return m, ErrUnsupported
			}
		}
		k, err = r.length()
		if err != nil {
			return m, err
		}
		data, err := r.take(k)
		if err != nil {
			return m, err
		}
		m.ix = append(m.ix, solInstruction{program: m.keys[p[0]].address(), accounts: accounts, data: data})
	}
	if versioned {
		tables, err := r.length()
		if err != nil {
			return m, err
		}
		if tables != 0 {
			return m, ErrUnsupported
		}
	}
	if len(r.data) != 0 {
		return m, ErrMalformed
	}
	return m, nil
}

func inspectSolana(_ Request, payload []byte, wallet Wallet, ctx InspectionContext) ([]Transfer, error) {
	m, err := solReadMessage(payload)
	if err != nil {
		return nil, err
	}
	pub, err := hex.DecodeString(wallet.PublicKeyHex)
	if err != nil || !bytes.Equal(pub, m.keys[0][:]) || wallet.Address != m.keys[0].address() {
		return nil, ErrSender
	}
	result := Transfer{From: wallet.Address}
	ix := m.ix
	// The transaction builder prepends these two instructions on mainnet. A fee
	// change is visible in the result even though it is not a transfer amount.
	if ix[0].program == solBudgetProgram {
		if len(ix) < 3 || ix[1].program != solBudgetProgram {
			return nil, ErrUnsupported
		}
		limit, price := ix[0], ix[1]
		if len(limit.accounts) != 0 || len(price.accounts) != 0 || len(limit.data) != 5 || limit.data[0] != 2 || len(price.data) != 9 || price.data[0] != 3 {
			return nil, ErrUnsupported
		}
		result.ComputeUnitLimit = binary.LittleEndian.Uint32(limit.data[1:])
		if result.ComputeUnitLimit == 0 || result.ComputeUnitLimit > 1_400_000 {
			return nil, ErrUnsupported
		}
		result.ComputeUnitPriceMicroLamports = strconv.FormatUint(binary.LittleEndian.Uint64(price.data[1:]), 10)
		ix = ix[2:]
	}
	last := ix[len(ix)-1]
	switch last.program {
	case solSystemProgram:
		if len(ix) != 1 || len(last.accounts) != 2 || len(last.data) != 12 || binary.LittleEndian.Uint32(last.data) != 2 {
			return nil, ErrUnsupported
		}
		if last.accounts[0] != 0 {
			return nil, ErrSender
		}
		dest := int(last.accounts[1])
		if dest == 0 || dest >= m.writable {
			return nil, ErrUnsupported
		}
		result.To = m.keys[dest].address()
		if ctx.TokenMint != "" || (ctx.RecipientOwner != "" && ctx.RecipientOwner != result.To) {
			return nil, ErrContext
		}
		result.AmountAtomic = strconv.FormatUint(binary.LittleEndian.Uint64(last.data[4:]), 10)
		result.Asset = Asset{Kind: "native"}
	case solTokenProgram:
		if err := m.tokenTransfer(ix, ctx, &result); err != nil {
			return nil, err
		}
	default:
		return nil, ErrUnsupported
	}
	if result.AmountAtomic == "0" {
		return nil, ErrUnsupported
	}
	return []Transfer{result}, nil
}

func (m solMessage) tokenTransfer(ix []solInstruction, ctx InspectionContext, result *Transfer) error {
	last := ix[len(ix)-1]
	var source, dest byte
	var mint, owner solKey
	var haveMint, haveOwner bool
	switch {
	case len(last.accounts) == 3 && len(last.data) == 9 && last.data[0] == 3: // Transfer
		source, dest = last.accounts[0], last.accounts[1]
	case len(last.accounts) == 4 && len(last.data) == 10 && last.data[0] == 12: // TransferChecked
		source, dest = last.accounts[0], last.accounts[2]
		mint = m.keys[last.accounts[1]]
		haveMint = true
		if int(last.accounts[1]) < m.writable {
			return ErrUnsupported
		}
	default:
		return ErrUnsupported
	}
	if last.accounts[len(last.accounts)-1] != 0 {
		return ErrSender
	}
	if source == dest || source == 0 || dest == 0 || int(source) >= m.writable || int(dest) >= m.writable {
		return ErrUnsupported
	}
	if len(ix) == 2 {
		create := ix[0]
		a := create.accounts
		if create.program != solATAProgram || len(a) != 6 || (len(create.data) != 0 && !(len(create.data) == 1 && (create.data[0] == 0 || create.data[0] == 1))) {
			return ErrUnsupported
		}
		if a[0] != 0 || a[1] != dest || int(a[3]) < m.writable || m.keys[a[4]].address() != solSystemProgram || m.keys[a[5]].address() != solTokenProgram || int(a[4]) < m.writable || int(a[5]) < m.writable {
			return ErrUnsupported
		}
		if haveMint && mint != m.keys[a[3]] {
			return ErrMalformed
		}
		mint, owner = m.keys[a[3]], m.keys[a[2]]
		haveMint, haveOwner = true, true
		result.CreatesDestinationAccount = true
	} else if len(ix) != 1 {
		return ErrUnsupported
	}
	if ctx.TokenMint != "" {
		expected, err := solParseAddress(ctx.TokenMint)
		if err != nil || (haveMint && mint != expected) {
			return ErrContext
		}
		mint = expected
		haveMint = true
	}
	if !haveMint {
		return ErrContext
	}
	if ctx.RecipientOwner != "" {
		expected, err := solParseAddress(ctx.RecipientOwner)
		if err != nil || (haveOwner && owner != expected) {
			return ErrContext
		}
		owner = expected
		haveOwner = true
	}
	sourceATA, err := solATA(m.keys[0], mint)
	if err != nil {
		return err
	}
	if m.keys[source] != sourceATA {
		return ErrSender
	}
	result.SourceAccount = m.keys[source].address()
	result.DestinationAccount = m.keys[dest].address()
	if haveOwner {
		target, err := solATA(owner, mint)
		if err != nil {
			return err
		}
		if m.keys[dest] != target {
			return ErrContext
		}
		result.To = owner.address()
	} else {
		result.To = result.DestinationAccount
		result.ToRole = "token_account"
	}
	result.AmountAtomic = strconv.FormatUint(binary.LittleEndian.Uint64(last.data[1:9]), 10)
	result.Asset = Asset{Kind: "token", Contract: mint.address()}
	return nil
}
