package id

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/renproject/surge"
)

// Constants represent the length of the variables.
const (
	SizeHintSignature = 65
	SizeHintSignatory = 32
)

// Signature defines an ECDSA signature of a Hash, encoded as [R || S || V]
// where V is either 0 or 1.
type Signature [SizeHintSignature]byte

// Signatory returns the that signed the Hash to produce this Signature.
func (signature Signature) Signatory(hash *Hash) (Signatory, error) {
	pubKey, err := crypto.SigToPub(hash[:], signature[:])
	if err != nil {
		return Signatory{}, fmt.Errorf("identifying signature=%v: %v", signature, err)
	}
	return NewSignatory((*PubKey)(pubKey)), nil
}

// Equal compares one Signature with another. If they are equal, then it returns
// true, otherwise it returns false.
func (signature Signature) Equal(other *Signature) bool {
	return bytes.Equal(signature[:], other[:])
}

// SizeHint returns the number of bytes required to represent a Signature in binary.
func (Signature) SizeHint() int {
	return SizeHintSignature
}

// Marshal into binary.
func (signature Signature) Marshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < SizeHintSignature || rem < SizeHintSignature {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}
	copy(buf, signature[:])
	return buf[SizeHintSignature:], rem - SizeHintSignature, nil
}

// Unmarshal from binary.
func (signature *Signature) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < SizeHintSignature || rem < SizeHintSignature {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}
	copy(signature[:], buf[:SizeHintSignature])
	return buf[SizeHintSignature:], rem - SizeHintSignature, nil
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
	if len(decoded) != SizeHintSignature {
		return fmt.Errorf("expected len=%v, got len=%v", SizeHintSignature, len(decoded))
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
type Signatory [SizeHintSignatory]byte

// NewSignatory returns the the Signatory of the given ECSDA.PublicKey
func NewSignatory(pubKey *PubKey) Signatory {
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

// SizeHint returns the number of bytes required to represent a Signatory in binary.
func (Signatory) SizeHint() int {
	return SizeHintSignatory
}

// Marshal into binary.
func (signatory Signatory) Marshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < SizeHintSignatory || rem < SizeHintSignatory {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}
	copy(buf, signatory[:])
	return buf[SizeHintSignatory:], rem - SizeHintSignatory, nil
}

// Unmarshal from binary.
func (signatory *Signatory) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < SizeHintSignatory || rem < SizeHintSignatory {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}
	copy(signatory[:], buf[:SizeHintSignatory])
	return buf[SizeHintSignatory:], rem - SizeHintSignatory, nil
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
	if len(decoded) != SizeHintSignatory {
		return fmt.Errorf("expected len=%v, got len=%v", SizeHintSignatory, len(decoded))
	}
	copy(signatory[:], decoded)
	return nil
}

// String returns the unpadded base64 URL string representation of the
// Signatory.
func (signatory Signatory) String() string {
	return base64.RawURLEncoding.EncodeToString(signatory[:])
}
