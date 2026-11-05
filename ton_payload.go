package signer

import (
	"bytes"
	"errors"

	"github.com/xssnick/tonutils-go/tvm/cell"
)

// Wallet V4R2 signing payloads contain ordinary cells. This intentionally excludes
// proof/exotic cells and stored hashes: the current cell parser does not validate
// their supplied hashes. Crypto Chief may send its computed digest explicitly.
const maxTONSigningCells = 16384

func tonCellDigest(b []byte) (digest []byte, err error) {
	if !validTONSigningBOC(b) {
		return nil, errors.New("invalid TON signing BOC: expected one complete bounded ordinary-cell graph")
	}
	// The pinned dependency contains panic-based parsing. Keep malformed public
	// data from terminating the merchant's key process even if a parser edge case
	// remains after bounded framing validation. No private key is accessed here.
	defer func() {
		if recover() != nil {
			digest = nil
			err = errors.New("invalid TON signing BOC")
		}
	}()
	c, err := cell.FromBOC(b)
	if err != nil {
		return nil, errors.New("invalid TON signing BOC")
	}
	return c.Hash(), nil
}

func validTONSigningBOC(b []byte) bool {
	if len(b) < 11 || !bytes.Equal(b[:4], []byte{0xb5, 0xee, 0x9c, 0x72}) {
		return false
	}
	flags, size, offSize := b[4], int(b[4]&7), int(b[5])
	// Cache and reserved flags are not used by the service's signing cell encoder.
	if flags&0x38 != 0 || size < 1 || size > 4 || offSize < 1 || offSize > 8 {
		return false
	}
	pos := 6
	read := func(n int) (int, bool) {
		if n > len(b)-pos {
			return 0, false
		}
		v := uint64(0)
		for _, c := range b[pos : pos+n] {
			v = v<<8 | uint64(c)
		}
		pos += n
		// Every count, offset and cell reference must fit within the actual input.
		if v > uint64(len(b)) {
			return 0, false
		}
		return int(v), true
	}
	cells, ok := read(size)
	if !ok || cells == 0 || cells > maxTONSigningCells {
		return false
	}
	roots, ok := read(size)
	if !ok || roots != 1 {
		return false
	}
	absent, ok := read(size)
	if !ok || absent != 0 {
		return false
	}
	dataLen, ok := read(offSize)
	if !ok || cells > dataLen/2 {
		return false
	}
	root, ok := read(size)
	if !ok || root != 0 {
		return false
	}
	var index []int
	if flags&0x80 != 0 {
		index = make([]int, cells)
		for i := range index {
			index[i], ok = read(offSize)
			if !ok || index[i] > dataLen || (i > 0 && index[i] <= index[i-1]) {
				return false
			}
		}
	}
	checksumSize := 0
	if flags&0x40 != 0 {
		checksumSize = 4
	}
	if dataLen != len(b)-pos-checksumSize {
		return false
	}
	data := b[pos : pos+dataLen]
	pos = 0
	refs := make([][]int, cells)
	for i := 0; i < cells; i++ {
		if len(data)-pos < 2 {
			return false
		}
		d1, d2 := data[pos], int(data[pos+1])
		pos += 2
		if d1&0xf8 != 0 || d1 > 4 {
			return false
		}
		n := (d2 + 1) / 2
		if n > len(data)-pos {
			return false
		}
		// Non-byte-aligned cells require a valid top-up bit and at least one bit.
		if d2&1 != 0 && (n == 0 || data[pos+n-1]&0x7f == 0) {
			return false
		}
		pos += n
		for j := 0; j < int(d1); j++ {
			if size > len(data)-pos {
				return false
			}
			v := uint64(0)
			for _, c := range data[pos : pos+size] {
				v = v<<8 | uint64(c)
			}
			pos += size
			// Forward-only references enforce a DAG and match service serialization.
			if v <= uint64(i) || v >= uint64(cells) {
				return false
			}
			refs[i] = append(refs[i], int(v))
		}
		if index != nil && index[i] != pos {
			return false
		}
	}
	if pos != len(data) {
		return false
	}
	depth := make([]int, cells)
	for i := cells - 1; i >= 0; i-- {
		for _, child := range refs[i] {
			if depth[child]+1 > depth[i] {
				depth[i] = depth[child] + 1
			}
		}
		if depth[i] > 1023 {
			return false
		}
	}
	// Reject hidden/unreachable cells: all supplied cell data belongs to the root
	// being signed, not a different unsigned graph appended to the same BOC.
	reachable := make([]bool, cells)
	reachable[0] = true
	for i := 0; i < cells; i++ {
		if !reachable[i] {
			return false
		}
		for _, child := range refs[i] {
			reachable[child] = true
		}
	}
	return true
}
