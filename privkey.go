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
	// PrivKeyLength is the length of an secp256k1 ECDSA private key in bytes.
	PrivKeyLength = 32
	// PubKeyLength is the length of an secp256k1 ECDSA public key in bytes.
	PubKeyLength = 64
)

// PrivKey is an secp256k1 ECDSA private key.
type PrivKey ecdsa.PrivateKey

// NewPrivKey generates a random PrivKey and returns it. This function will
// panic if there is an error generating the PrivKey.
func NewPrivKey() *PrivKey {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	return (*PrivKey)(privKey)
}

// Sign a Hash and return the resulting Signature, or error.
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

// Signatory returns the public identity generated from the public key
// associated with this PrivKey.
func (privKey PrivKey) Signatory() Signatory {
	return NewSignatory(&privKey.PublicKey)
}

// SizeHint returns the numbers of bytes required to represent this PrivKey in
// binary.
func (privKey PrivKey) SizeHint() int {
	return 32
}

// Marshal this PrivKey into binary.
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

// Unmarshal from binary into this PrivKey.
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
