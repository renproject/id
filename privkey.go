package id

import (
	"crypto/ecdsa"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/renproject/surge"
)

const (
	PrivKeyLength = 32
	PubKeyLength  = 64
)

type PrivKey ecdsa.PrivateKey

func NewPrivKey() *PrivKey {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	return (*PrivKey)(privKey)
}

func (privKey PrivKey) Sign(hash *Hash) (Signature, error) {
	rsv, err := crypto.Sign(hash[:], (*ecdsa.PrivateKey)(&privKey))
	if err != nil {
		return Signature{}, err
	}
	if len(rsv) != 65 {
		panic(fmt.Errorf("expected len=65, got len=%v", len(rsv)))
	}
	signature := Signature{}
	copy(signature[:], rsv)
	return signature, nil
}

func (privKey PrivKey) Signatory() Signatory {
	return NewSignatory(&privKey.PublicKey)
}

func (privKey PrivKey) SizeHint() int {
	return 32
}

func (privKey PrivKey) Marshal(w io.Writer, m int) (int, error) {
	if m < 32 {
		return m, surge.ErrMaxBytesExceeded
	}
	data := [32]byte{}
	d := privKey.D.Bytes()
	if len(d) > 32 {
		panic(fmt.Errorf("expected len<=32, got len=%v", len(d)))
	}
	copy(data[32-len(d):], d)
	n, err := w.Write(data[:])
	return m - n, err
}

func (privKey *PrivKey) Unmarshal(r io.Reader, m int) (int, error) {
	if m < 32 {
		return m, surge.ErrMaxBytesExceeded
	}
	data := [32]byte{}
	n, err := r.Read(data[:])
	if err != nil {
		return m - n, err
	}
	if n != 32 {
		return m - n, fmt.Errorf("expected privkey len=32, got privkey len=%v", n)
	}
	x, y := crypto.S256().ScalarBaseMult(data[:])
	privKey.D = new(big.Int).SetBytes(data[:])
	privKey.PublicKey = ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     x,
		Y:     y,
	}
	return m - n, nil
}
