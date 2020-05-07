package id

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/renproject/surge"
)

// Constants represent the length of the variables.
const (
	SignatureLength = 65
	SignatoryLength = 32
)

// Signature defines an ECDSA signature of a Hash, encoded as [R || S || V]
// where V is either 0 or 1.
type Signature [65]byte

// Signatory returns the that signed the Hash to produce this Signature.
func (signature Signature) Signatory(hash *Hash) (Signatory, error) {
	pubKey, err := crypto.SigToPub(hash[:], signature[:])
	if err != nil {
		return Signatory{}, fmt.Errorf("identifying signature=%v: %v", signature, err)
	}
	return NewSignatory(pubKey), nil
}

// Equal compares one Signature with another. If they are equal, then it returns
// true, otherwise it returns false.
func (signature Signature) Equal(other *Signature) bool {
	return bytes.Equal(signature[:], other[:])
}

// SizeHint returns the number of bytes required to represent this Signature in
// binary.
func (signature Signature) SizeHint() int {
	return 65
}

// Marshal this Signature into binary.
func (signature Signature) Marshal(w io.Writer, m int) (int, error) {
	if m < 65 {
		return m, surge.ErrMaxBytesExceeded
	}
	n, err := w.Write(signature[:])
	if n != 65 {
		return m - n, fmt.Errorf("expected signature len=65, got signature len=%v", n)
	}
	return m - n, err
}

// Unmarshal from binary into this Signature.
func (signature *Signature) Unmarshal(r io.Reader, m int) (int, error) {
	if m < 65 {
		return m, surge.ErrMaxBytesExceeded
	}
	n, err := r.Read(signature[:])
	if n != 65 {
		return m - n, fmt.Errorf("expected signature len=65, got signature len=%v", n)
	}
	return m - n, err
}

// MarshalJSON implements the JSON marshaler interface for the Signature type.
// It is represented as an unpadded base64 string.
func (signature Signature) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(signature[:]))
}

// UnmarshalJSON implements the JSON unmarshaler interface for the Signature
// type. It assumes that it has been represented as an unpadded base64 string.
func (signature *Signature) UnmarshalJSON(data []byte) error {
	str := ""
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	if len(decoded) != 65 {
		return fmt.Errorf("expected len=65, got len=%v", len(decoded))
	}
	copy(signature[:], decoded)
	return nil
}

// String returns the unpadded base64 URL string representation of the
// Signature.
func (signature Signature) String() string {
	return base64.RawURLEncoding.EncodeToString(signature[:])
}

// Signatory defines the Hash of the ECDSA public key that is recovered from a
// Signature.
type Signatory [32]byte

// NewSignatory returns the the Signatory of the given ECSDA.PublicKey
func NewSignatory(pubKey *ecdsa.PublicKey) Signatory {
	x := [32]byte{}
	xData := pubKey.X.Bytes()
	copy(x[32-len(xData):], xData)

	y := [32]byte{}
	yData := pubKey.Y.Bytes()
	copy(y[32-len(yData):], yData)

	pubKeyData := append(x[:], y[:]...)
	return Signatory(sha256.Sum256(pubKeyData))
}

// Equal compares one Signatory with another. If they are equal, then it returns
// true, otherwise it returns false.
func (signatory Signatory) Equal(other *Signatory) bool {
	return bytes.Equal(signatory[:], other[:])
}

// SizeHint returns the number of bytes required to represent this Signatory in
// binary.
func (signatory Signatory) SizeHint() int {
	return 32
}

// Marshal this Signatory into binary.
func (signatory Signatory) Marshal(w io.Writer, m int) (int, error) {
	if m < 32 {
		return m, surge.ErrMaxBytesExceeded
	}
	n, err := w.Write(signatory[:])
	if n != 32 {
		return m - n, fmt.Errorf("expected signatory len=32, got signatory len=%v", n)
	}
	return m - n, err
}

// Unmarshal from binary into this Signatory.
func (signatory *Signatory) Unmarshal(r io.Reader, m int) (int, error) {
	if m < 32 {
		return m, surge.ErrMaxBytesExceeded
	}
	n, err := r.Read(signatory[:])
	if n != 32 {
		return m - n, fmt.Errorf("expected signatory len=32, got signatory len=%v", n)
	}
	return m - n, err
}

// MarshalJSON implements the JSON marshaler interface for the Signatory type.
// It is represented as an unpadded base64 string.
func (signatory Signatory) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(signatory[:]))
}

// UnmarshalJSON implements the JSON unmarshaler interface for the Signatory
// type. It assumes that it has been represented as an unpadded base64 string.
func (signatory *Signatory) UnmarshalJSON(data []byte) error {
	str := ""
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	if len(decoded) != 32 {
		return fmt.Errorf("expected len=32, got len=%v", len(decoded))
	}
	copy(signatory[:], decoded)
	return nil
}

// String returns the unpadded base64 URL string representation of the
// Signatory.
func (signatory Signatory) String() string {
	return base64.RawURLEncoding.EncodeToString(signatory[:])
}
