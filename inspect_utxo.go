package signer

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
)

type utxoInput struct {
	point        []byte // 32-byte wire-order txid followed by the four-byte output index
	scriptSizeAt int
	script       []byte
	sequence     []byte
}

type utxoOutput struct {
	value  uint64
	script []byte
}

type utxoTransaction struct {
	raw         []byte
	inputs      []utxoInput
	outputs     []utxoOutput
	outputBytes []byte // concatenated wire outputs without their count
	txid        [32]byte
	hasWitness  bool
}

// utxoReader bounds both CompactSize lengths and counts before allocation.
type utxoReader struct {
	data []byte
	pos  int
	err  error
}

func (r *utxoReader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.data)-r.pos {
		r.err = ErrMalformed
		return nil
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b
}

func (r *utxoReader) count(limit int) int {
	prefix := r.take(1)
	if prefix == nil {
		return 0
	}
	n := uint64(prefix[0])
	switch prefix[0] {
	case 0xfd:
		b := r.take(2)
		if b == nil {
			return 0
		}
		n = uint64(binary.LittleEndian.Uint16(b))
		if n < 0xfd {
			r.err = ErrMalformed
		}
	case 0xfe:
		b := r.take(4)
		if b == nil {
			return 0
		}
		n = uint64(binary.LittleEndian.Uint32(b))
		if n <= math.MaxUint16 {
			r.err = ErrMalformed
		}
	case 0xff:
		b := r.take(8)
		if b == nil {
			return 0
		}
		n = binary.LittleEndian.Uint64(b)
		if n <= math.MaxUint32 {
			r.err = ErrMalformed
		}
	}
	if r.err != nil || n > uint64(limit) {
		r.err = ErrMalformed
		return 0
	}
	return int(n)
}

func (r *utxoReader) blob() []byte { return r.take(r.count(len(r.data) - r.pos)) }

func utxoDoubleHash(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return sha256.Sum256(h.Sum(nil))
}

// Decode the ordinary Bitcoin-family serialization. Witnesses in a funding
// transaction are excluded from its txid. Other optional serialization flags
// (including Litecoin MWEB) are outside the transfer formats inspected here.
func readUtxoTransaction(rawHex string) (*utxoTransaction, error) {
	if len(rawHex) < 20 || len(rawHex) > 2*MaxPayloadBytes {
		return nil, ErrMalformed
	}
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, ErrMalformed
	}
	r := utxoReader{data: raw, pos: 4}
	tx := &utxoTransaction{raw: raw}
	if raw[4] == 0 {
		if raw[5] != 1 {
			return nil, ErrUnsupported
		}
		tx.hasWitness = true
		r.pos += 2
	}
	baseStart := r.pos
	inCount := r.count((len(raw) - r.pos) / 41)
	if inCount == 0 {
		return nil, ErrMalformed
	}
	tx.inputs = make([]utxoInput, inCount)
	for i := range tx.inputs {
		in := &tx.inputs[i]
		in.point = r.take(36)
		in.scriptSizeAt = r.pos
		in.script = r.blob()
		in.sequence = r.take(4)
		if r.err != nil {
			return nil, r.err
		}
	}
	outCount := r.count((len(raw) - r.pos) / 9)
	if outCount == 0 {
		return nil, ErrMalformed
	}
	outputsStart := r.pos
	tx.outputs = make([]utxoOutput, outCount)
	for i := range tx.outputs {
		amount := r.take(8)
		if amount == nil {
			return nil, ErrMalformed
		}
		out := &tx.outputs[i]
		out.value = binary.LittleEndian.Uint64(amount)
		out.script = r.blob()
		if out.value > math.MaxInt64 || r.err != nil {
			return nil, ErrMalformed
		}
	}
	baseEnd := r.pos
	tx.outputBytes = raw[outputsStart:baseEnd]
	if tx.hasWitness {
		hasStack := false
		for range tx.inputs {
			n := r.count(len(raw) - r.pos)
			if n > 0 {
				hasStack = true
			}
			for j := 0; j < n && r.err == nil; j++ {
				r.blob()
			}
			if r.err != nil {
				return nil, r.err
			}
		}
		if !hasStack {
			return nil, ErrMalformed
		}
	}
	locktime := r.take(4)
	if r.err != nil || r.pos != len(raw) {
		return nil, ErrMalformed
	}
	tx.txid = utxoDoubleHash(raw[:4], raw[baseStart:baseEnd], locktime)
	return tx, nil
}

type utxoNetwork struct {
	witnessHRP    string
	cashPrefix    string
	pubKeyVersion byte
	scriptVersion byte
}

func inspectionUTXONetwork(f Family) (utxoNetwork, error) {
	switch f {
	case BTC:
		return utxoNetwork{witnessHRP: "bc", pubKeyVersion: 0x00, scriptVersion: 0x05}, nil
	case BTCTestnet:
		return utxoNetwork{witnessHRP: "tb", pubKeyVersion: 0x6f, scriptVersion: 0xc4}, nil
	case LTC:
		return utxoNetwork{witnessHRP: "ltc", pubKeyVersion: 0x30, scriptVersion: 0x32}, nil
	case LTCTestnet:
		return utxoNetwork{witnessHRP: "tltc", pubKeyVersion: 0x6f, scriptVersion: 0xc4}, nil
	case BCH:
		return utxoNetwork{cashPrefix: "bitcoincash"}, nil
	case BCHTestnet:
		return utxoNetwork{cashPrefix: "bchtest"}, nil
	case DOGE:
		return utxoNetwork{pubKeyVersion: 0x1e, scriptVersion: 0x16}, nil
	case DOGETestnet:
		return utxoNetwork{pubKeyVersion: 0x71, scriptVersion: 0xc4}, nil
	default:
		return utxoNetwork{}, ErrUnsupported
	}
}

func (n utxoNetwork) address(hash []byte) string {
	switch {
	case n.witnessHRP != "":
		return walletWitnessAddress(n.witnessHRP, hash)
	case n.cashPrefix != "":
		return walletCashAddress(n.cashPrefix, hash)
	default:
		return walletBase58Check(n.pubKeyVersion, hash, bitcoinAlphabet)
	}
}

// Decode standard address outputs without interpreting arbitrary script.
func (n utxoNetwork) outputAddress(script []byte) (string, error) {
	switch {
	case len(script) == 25 && bytes.Equal(script[:3], []byte{0x76, 0xa9, 20}) && bytes.Equal(script[23:], []byte{0x88, 0xac}):
		if n.cashPrefix != "" {
			return walletCashAddress(n.cashPrefix, script[3:23]), nil
		}
		return walletBase58Check(n.pubKeyVersion, script[3:23], bitcoinAlphabet), nil
	case len(script) == 23 && script[0] == 0xa9 && script[1] == 20 && script[22] == 0x87:
		if n.cashPrefix != "" {
			return encodeCashAddress(n.cashPrefix, 8, script[2:22]), nil
		}
		return walletBase58Check(n.scriptVersion, script[2:22], bitcoinAlphabet), nil
	case n.witnessHRP != "" && (len(script) == 22 || len(script) == 34) && script[0] == 0 && int(script[1]) == len(script)-2:
		return encodeWitnessProgram(n.witnessHRP, 0, script[2:]), nil
	case n.witnessHRP != "" && len(script) == 34 && script[0] == 0x51 && script[1] == 32:
		return encodeWitnessProgram(n.witnessHRP, 1, script[2:]), nil
	}
	return "", ErrUnsupported
}

func (tx *utxoTransaction) signatureHash(index int, scriptCode []byte, inputValue uint64, typ uint32, legacy bool) [32]byte {
	in := tx.inputs[index]
	hashType := binary.LittleEndian.AppendUint32(nil, typ)
	// P2PKH scriptCode is exactly 25 bytes. Its canonical CompactSize prefix is one byte.
	subscript := append([]byte{byte(len(scriptCode))}, scriptCode...)
	if legacy {
		// All input scripts were checked empty. Replace just the selected
		// input's zero length in the canonical unsigned serialization.
		return utxoDoubleHash(tx.raw[:in.scriptSizeAt], subscript, tx.raw[in.scriptSizeAt+1:], hashType)
	}
	var points, sequences bytes.Buffer
	for _, input := range tx.inputs {
		points.Write(input.point)
		sequences.Write(input.sequence)
	}
	prevouts := utxoDoubleHash(points.Bytes())
	seq := utxoDoubleHash(sequences.Bytes())
	outputs := utxoDoubleHash(tx.outputBytes)
	return utxoDoubleHash(tx.raw[:4], prevouts[:], seq[:], in.point, subscript,
		binary.LittleEndian.AppendUint64(nil, inputValue), in.sequence, outputs[:], tx.raw[len(tx.raw)-4:], hashType)
}

func inspectUTXO(req Request, payload []byte, wallet Wallet, ctx InspectionContext) ([]Transfer, string, error) {
	network, err := inspectionUTXONetwork(req.Family)
	if err != nil {
		return nil, "", err
	}
	if ctx.InputIndex == nil || ctx.PayloadHex == "" || len(ctx.PreviousTransactions) == 0 {
		return nil, "", ErrContext
	}
	tx, err := readUtxoTransaction(ctx.PayloadHex)
	if err != nil {
		return nil, "", err
	}
	if tx.hasWitness {
		return nil, "", ErrUnsupported
	}
	if uint64(*ctx.InputIndex) >= uint64(len(tx.inputs)) || len(ctx.PreviousTransactions) > len(tx.inputs) {
		return nil, "", ErrContext
	}
	pub, err := hex.DecodeString(wallet.PublicKeyHex)
	if err != nil || len(pub) != btcec.PubKeyBytesLenCompressed {
		return nil, "", ErrSender
	}
	if _, err := btcec.ParsePubKey(pub); err != nil {
		return nil, "", ErrSender
	}
	keyHash := walletHash160(pub)
	if network.address(keyHash) != wallet.Address {
		return nil, "", ErrSender
	}
	scriptCode := append([]byte{0x76, 0xa9, 20}, keyHash...)
	scriptCode = append(scriptCode, 0x88, 0xac)
	fundingScript := scriptCode
	if network.witnessHRP != "" {
		fundingScript = append([]byte{0, 20}, keyHash...)
	}

	wanted := make(map[[32]byte]*utxoTransaction)
	seen := make(map[[36]byte]bool)
	for _, in := range tx.inputs {
		if len(in.script) != 0 {
			return nil, "", ErrUnsupported
		}
		point := [36]byte(in.point)
		if seen[point] {
			return nil, "", ErrMalformed
		}
		seen[point] = true
		wanted[[32]byte(in.point[:32])] = nil
	}
	if len(ctx.PreviousTransactions) != len(wanted) {
		return nil, "", ErrContext
	}
	var totalBytes int
	for _, raw := range ctx.PreviousTransactions {
		if len(raw) > 2*MaxBatchPayloadBytes-totalBytes {
			return nil, "", ErrContext
		}
		totalBytes += len(raw)
		prev, err := readUtxoTransaction(raw)
		if err != nil {
			return nil, "", err
		}
		if prev.hasWitness && network.witnessHRP == "" {
			return nil, "", ErrUnsupported
		}
		if existing, ok := wanted[prev.txid]; !ok || existing != nil {
			return nil, "", ErrMismatch
		}
		wanted[prev.txid] = prev
	}
	var inputSum, selectedAmount uint64
	for i, in := range tx.inputs {
		prev := wanted[[32]byte(in.point[:32])]
		vout := binary.LittleEndian.Uint32(in.point[32:])
		if prev == nil || uint64(vout) >= uint64(len(prev.outputs)) {
			return nil, "", ErrMismatch
		}
		out := prev.outputs[vout]
		if !bytes.Equal(out.script, fundingScript) {
			return nil, "", ErrSender
		}
		if out.value > math.MaxInt64-inputSum {
			return nil, "", ErrMalformed
		}
		inputSum += out.value
		if uint32(i) == *ctx.InputIndex {
			selectedAmount = out.value
		}
	}
	expectedHashType := uint32(1)
	if network.cashPrefix != "" {
		expectedHashType = 0x41
	}
	if req.HashType != expectedHashType || req.PayloadType != Digest {
		return nil, "", ErrUnsupported
	}
	legacy := network.witnessHRP == "" && network.cashPrefix == ""
	digest := tx.signatureHash(int(*ctx.InputIndex), scriptCode, selectedAmount, req.HashType, legacy)
	if !bytes.Equal(digest[:], payload) {
		return nil, "", ErrMismatch
	}
	left := inputSum
	transfers := make([]Transfer, 0, len(tx.outputs))
	for _, out := range tx.outputs {
		to, err := network.outputAddress(out.script)
		if err != nil {
			return nil, "", err
		}
		if out.value > left {
			return nil, "", ErrMalformed
		}
		left -= out.value
		transfers = append(transfers, Transfer{From: wallet.Address, To: to, AmountAtomic: strconv.FormatUint(out.value, 10), Asset: Asset{Kind: "native"}})
	}
	return transfers, strconv.FormatUint(left, 10), nil
}
