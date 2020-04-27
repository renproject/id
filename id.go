package id

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"github.com/renproject/abi"
)

// Constants represent the length of the variables.
const (
	SignatureLength = 65
	SignatoryLength = 32
)

// Signature defines the ECDSA signature of a Hash. Encoded as R, S, V.
type Signature abi.Bytes65

// Equal compares one Signature with another.
func (signature Signature) Equal(other *Signature) bool {
	return bytes.Equal(signature[:], other[:])
}

// SizeHint returns the number of bytes required to represent this Signature in
// binary.
func (signature Signature) SizeHint() int {
	return 65
}

// Marshal this Signature to binary.
func (signature Signature) Marshal(w io.Writer, m int) (int, error) {
	return abi.Bytes65(signature).Marshal(w, m)
}

// Unmarshal into this Signature from binary.
func (signature *Signature) Unmarshal(r io.Reader, m int) (int, error) {
	return (*abi.Bytes65)(signature).Unmarshal(r, m)
}

// MarshalJSON by encoding it as base64.
func (signature Signature) MarshalJSON() ([]byte, error) {
	return abi.Bytes65(signature).MarshalJSON()
}

// UnmarshalJSON by decoding it from base64.
func (signature *Signature) UnmarshalJSON(data []byte) error {
	return (*abi.Bytes65)(signature).UnmarshalJSON(data)
}

// String returns the unpadded base64 URL string representation of the
// Signature.
func (signature Signature) String() string {
	return base64.RawURLEncoding.EncodeToString(signature[:])
}

// Signatory defines the Hash of the ECDSA public key that is recovered from a
// Signature.
type Signatory abi.Bytes32

// NewSignatory returns the the Signatory of the given ECSDA.PublicKey
func NewSignatory(pubKey *ecdsa.PublicKey) Signatory {
	pubKeyBytes := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)
	return Signatory(sha256.Sum256(pubKeyBytes))
}

// Equal compares one Signatory with another.
func (signatory Signatory) Equal(other *Signatory) bool {
	return bytes.Equal(signatory[:], other[:])
}

// SizeHint returns the number of bytes required to represent this Signatory in
// binary.
func (signatory Signatory) SizeHint() int {
	return 32
}

// Marshal this Signatory to binary.
func (signatory Signatory) Marshal(w io.Writer, m int) (int, error) {
	return abi.Bytes32(signatory).Marshal(w, m)
}

// Unmarshal into this Signatory from binary.
func (signatory *Signatory) Unmarshal(r io.Reader, m int) (int, error) {
	return (*abi.Bytes32)(signatory).Unmarshal(r, m)
}

func (signatory Signatory) MarshalJSON() ([]byte, error) {
	return abi.Bytes32(signatory).MarshalJSON()
}

func (signatory *Signatory) UnmarshalJSON(data []byte) error {
	return (*abi.Bytes32)(signatory).UnmarshalJSON(data)
}

// String returns the unpadded base64 URL string representation of the
// Signatory.
func (signatory Signatory) String() string {
	return base64.RawURLEncoding.EncodeToString(signatory[:])
}
