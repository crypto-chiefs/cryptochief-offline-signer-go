package signer

import (
	"encoding/hex"
	"unicode/utf8"

	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

// Both accepted TON input forms have passed the SDK's bounded, ordinary-cell
// BOC validation. MustLoad methods in tonutils panic on a truncated TL-B field.
func inspectTON(raw []byte, wallet Wallet) (payments []Transfer, err error) {
	defer func() {
		if recover() != nil {
			payments = nil
			err = ErrMalformed
		}
	}()
	account, err := address.ParseAddr(wallet.Address)
	if err != nil {
		return nil, ErrSender
	}
	pub, err := hex.DecodeString(wallet.PublicKeyHex)
	if err != nil || len(pub) != 32 {
		return nil, ErrSender
	}
	derived, err := tonWalletAddress(pub, WalletOptions{Family: TON, TONTestnet: account.IsTestnetOnly(), TONNonBounceable: !account.IsBounceable()})
	if err != nil || derived != wallet.Address {
		return nil, ErrSender
	}
	c, err := cell.FromBOC(raw)
	if err != nil {
		return nil, ErrMalformed
	}
	root := c.BeginParse()
	if root.MustLoadUInt(32) != 698983191 {
		return nil, ErrUnsupported
	}
	root.MustLoadUInt(32) // valid_until
	root.MustLoadUInt(32) // seqno
	if root.MustLoadUInt(8) != 0 {
		return nil, ErrUnsupported
	} // ordinary V4R2 send
	count := root.RefsNum()
	if count == 0 || root.BitsLeft() != uint(count*8) {
		return nil, ErrMalformed
	}
	for i := 0; i < count; i++ {
		// The builder pays fees separately. Send-all and carry-remaining
		// modes cannot be described as a fixed, offline amount.
		if root.MustLoadUInt(8) != 3 {
			return nil, ErrUnsupported
		}
		t, err := tonMessage(root.MustLoadRef(), account)
		if err != nil {
			return nil, err
		}
		payments = append(payments, t)
	}
	return payments, nil
}

func tonStdAddress(s *cell.Slice, testOnly, bounce bool) (*address.Address, error) {
	// addr_std$10, anycast absent. The generic loader discards the anycast
	// prefix; inspect the tag before letting it consume an address.
	if s.Copy().MustLoadUInt(3) != 4 {
		return nil, ErrUnsupported
	}
	a := s.MustLoadAddr()
	a.SetTestnetOnly(testOnly)
	a.SetBounce(bounce)
	return a, nil
}

func tonBody(s *cell.Slice) (*cell.Slice, error) {
	if !s.MustLoadBoolBit() {
		return s, nil
	}
	b := s.MustLoadRef()
	if s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return nil, ErrUnsupported
	}
	return b, nil
}

func tonComment(s *cell.Slice) (string, error) {
	if s.BitsLeft() == 0 && s.RefsNum() == 0 {
		return "", nil
	}
	if s.MustLoadUInt(32) != 0 {
		return "", ErrUnsupported
	}
	var text []byte
	for {
		if s.BitsLeft()%8 != 0 || s.RefsNum() > 1 || len(text) > MaxPayloadBytes {
			return "", ErrMalformed
		}
		text = append(text, s.MustLoadSlice(s.BitsLeft())...)
		if s.RefsNum() == 0 {
			break
		}
		s = s.MustLoadRef()
	}
	if !utf8.Valid(text) {
		return "", ErrUnsupported
	}
	return string(text), nil
}

func tonMessage(msg *cell.Slice, owner *address.Address) (Transfer, error) {
	var zero Transfer
	if msg.MustLoadUInt(2) != 1 {
		return zero, ErrUnsupported
	} // internal message, IHR disabled
	bounce := msg.MustLoadBoolBit()
	if msg.MustLoadBoolBit() || msg.MustLoadUInt(2) != 0 {
		return zero, ErrUnsupported
	} // bounced / explicit source
	dst, err := tonStdAddress(msg, owner.IsTestnetOnly(), bounce)
	if err != nil {
		return zero, err
	}
	amount := msg.MustLoadBigCoins()
	if msg.MustLoadBoolBit() || msg.MustLoadBigCoins().Sign() != 0 || msg.MustLoadBigCoins().Sign() != 0 ||
		msg.MustLoadUInt(64) != 0 || msg.MustLoadUInt(32) != 0 || msg.MustLoadBoolBit() {
		return zero, ErrUnsupported // extra currency, fee overrides, time or state init
	}
	body, err := tonBody(msg)
	if err != nil {
		return zero, err
	}
	t := Transfer{From: owner.String(), To: dst.String(), AmountAtomic: amount.String(), Asset: Asset{Kind: "native"}}
	if body.BitsLeft() < 32 || body.Copy().MustLoadUInt(32) == 0 {
		t.Memo, err = tonComment(body)
		return t, err
	}
	if body.MustLoadUInt(32) != 0x0f8a7ea5 {
		return zero, ErrUnsupported
	}
	body.MustLoadUInt(64) // TEP-74 query_id
	t.AmountAtomic = body.MustLoadBigCoins().String()
	to, err := tonStdAddress(body, owner.IsTestnetOnly(), true)
	if err != nil {
		return zero, err
	}
	refund, err := tonStdAddress(body, owner.IsTestnetOnly(), true)
	if err != nil || !refund.Equals(owner) || body.MustLoadBoolBit() {
		return zero, ErrUnsupported
	}
	t.To = to.String()
	// TEP-74 names the sender's jetton-wallet contract, not its master.
	// Consumers match this account against their trusted per-wallet asset map.
	t.Asset = Asset{Kind: "jetton_wallet", Contract: dst.String()}
	t.AttachedNativeAtomic = amount.String()
	t.ForwardNativeAtomic = body.MustLoadBigCoins().String()
	forward, err := tonBody(body)
	if err != nil {
		return zero, err
	}
	t.Memo, err = tonComment(forward)
	return t, err
}
