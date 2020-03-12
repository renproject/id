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
	HashLength      = 32
	SignatureLength = 65
	SignatoryLength = 32
)

// Hashes defines a wrapper type around the []Hash type.
type Hashes []Hash

// Equal compares one Hashes with another.
func (hashes Hashes) Equal(other Hashes) bool {
	if len(hashes) != len(other) {
		return false
	}
	for i := range hashes {
		if !hashes[i].Equal(other[i]) {
			return false
		}
	}
	return true
}

// Hash defines the output of the 256-bit SHA2 hashing function.
type Hash abi.Bytes32

// Equal compares one Hash with another.
func (hash Hash) Equal(other Hash) bool {
	return bytes.Equal(hash[:], other[:])
}

func (hash Hash) SizeHint() int {
	return 32
}

func (hash Hash) Marshal(w io.Writer, m int) (int, error) {
	return abi.Bytes32(hash).Marshal(w, m)
}

func (hash *Hash) Unmarshal(r io.Reader, m int) (int, error) {
	return (*abi.Bytes32)(hash).Unmarshal(r, m)
}

func (hash Hash) MarshalJSON() ([]byte, error) {
	return abi.Bytes32(hash).MarshalJSON()
}

func (hash *Hash) UnmarshalJSON(data []byte) error {
	return (*abi.Bytes32)(hash).UnmarshalJSON(data)
}

func (hash Hash) String() string {
	return base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}

// Signatures defines a wrapper type around the []Signature type.
type Signatures []Signature

// Equal compares one Hashes with another.
func (sigs Signatures) Equal(other Signatures) bool {
	if len(sigs) != len(other) {
		return false
	}
	for i := range sigs {
		if !sigs[i].Equal(other[i]) {
			return false
		}
	}
	return true
}

// Hash returns a 256-bit SHA2 hash of the Signatures by converting them into
// bytes and concatenating them to each other.
func (sigs Signatures) Hash() Hash {
	data := make([]byte, 0, 64*len(sigs))
	for _, sig := range sigs {
		data = append(data, sig[:]...)
	}
	return sha256.Sum256(data)
}

// String implements the `fmt.Stringer` interface for the Signatures type.
func (sigs Signatures) String() string {
	hash := sigs.Hash()
	return base64.RawStdEncoding.EncodeToString(hash[:])
}

// Signature defines the ECDSA signature of a Hash. Encoded as R, S, V.
type Signature abi.Bytes65

// Equal compares one Signature with another.
func (sig Signature) Equal(other Signature) bool {
	return bytes.Equal(sig[:], other[:])
}

func (sig Signature) SizeHint() int {
	return 65
}

func (sig Signature) Marshal(w io.Writer, m int) (int, error) {
	return abi.Bytes65(sig).Marshal(w, m)
}

func (sig *Signature) Unmarshal(r io.Reader, m int) (int, error) {
	return (*abi.Bytes65)(sig).Unmarshal(r, m)
}

func (sig Signature) MarshalJSON() ([]byte, error) {
	return abi.Bytes65(sig).MarshalJSON()
}

func (sig *Signature) UnmarshalJSON(data []byte) error {
	return (*abi.Bytes65)(sig).UnmarshalJSON(data)
}

// String implements the `fmt.Stringer` interface for the Hash type.
func (sig Signature) String() string {
	return base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(sig[:])
}

// Signatories defines a wrapper type around the []Signatory type.
type Signatories []Signatory

// Hash returns a 256-bit SHA2 hash of the Signatories by converting them into
// bytes and concatenating them to each other.
func (sigs Signatories) Hash() Hash {
	data := make([]byte, 0, 32*len(sigs))
	for _, sig := range sigs {
		data = append(data, sig[:]...)
	}
	return sha256.Sum256(data)
}

func (sigs Signatories) Equal(other Signatories) bool {
	if len(sigs) != len(other) {
		return false
	}
	for i := range sigs {
		if !sigs[i].Equal(other[i]) {
			return false
		}
	}
	return true
}

// String implements the `fmt.Stringer` interface for the Signatories type.
func (sigs Signatories) String() string {
	hash := sigs.Hash()
	return base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}

// Signatory defines the Hash of the ECDSA public key that is recovered from a
// Signature.
type Signatory abi.Bytes32

// NewSignatory returns the the Signatory of the given ECSDA.PublicKey
func NewSignatory(pubKey ecdsa.PublicKey) Signatory {
	pubKeyBytes := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)
	return Signatory(sha256.Sum256(pubKeyBytes))
}

// Equal compares one Signatory with another.
func (sig Signatory) Equal(other Signatory) bool {
	return bytes.Equal(sig[:], other[:])
}

func (sig Signatory) SizeHint() int {
	return 32
}

func (sig Signatory) Marshal(w io.Writer, m int) (int, error) {
	return abi.Bytes32(sig).Marshal(w, m)
}

func (sig *Signatory) Unmarshal(r io.Reader, m int) (int, error) {
	return (*abi.Bytes32)(sig).Unmarshal(r, m)
}

func (sig Signatory) MarshalJSON() ([]byte, error) {
	return abi.Bytes32(sig).MarshalJSON()
}

func (sig *Signatory) UnmarshalJSON(data []byte) error {
	return (*abi.Bytes32)(sig).UnmarshalJSON(data)
}

func (sig Signatory) String() string {
	return base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(sig[:])
}
