package id

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/renproject/surge"
)

const (
	// SizeHintPubKey is the number of bytes required to represent a secp256k1
	// ECDSA public key in binary.
	SizeHintPubKey = 33
	// SizeHintPrivKey is the number of bytes required to represent a secp256k1
	// ECDSA private key in binary.
	SizeHintPrivKey = 32
)

// PubKey is a secp256k1 ECDSA public key.
type PubKey ecdsa.PublicKey

// SizeHint returns the number of bytes required to represent the PubKey in
// binary.
func (pubKey PubKey) SizeHint() int {
	return SizeHintPubKey
}

// Marshal to binary.
func (pubKey PubKey) Marshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < SizeHintPubKey || rem < SizeHintPubKey {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}
	data := crypto.CompressPubkey((*ecdsa.PublicKey)(&pubKey))
	if len(data) != SizeHintPubKey {
		// Defensive check. The CompressPubkey function currently guarantees
		// that it returns exacty 33 bytes, but there is no guarantee that this
		// will not change in future versions.
		panic(fmt.Errorf("expected len=%v, got len=%v", SizeHintPubKey, len(data)))
	}
	copy(buf, data)
	buf = buf[SizeHintPubKey:]
	rem -= SizeHintPubKey
	return buf, rem, nil
}

// Unmarshal from binary.
func (pubKey *PubKey) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < SizeHintPubKey || rem < SizeHintPubKey {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}
	decompressed, err := crypto.DecompressPubkey(buf[:SizeHintPubKey])
	if err != nil {
		return buf[SizeHintPubKey:], rem - SizeHintPubKey, err
	}
	if decompressed == nil {
		return buf[SizeHintPubKey:], rem - SizeHintPubKey, fmt.Errorf("decompressed pubkey=nil")
	}
	*pubKey = (PubKey)(*decompressed)
	return buf[SizeHintPubKey:], rem - SizeHintPubKey, nil
}

// MarshalJSON implements the JSON marshaler interface by representing this
// private key as an unpadded base64 string.
func (pubKey PubKey) MarshalJSON() ([]byte, error) {
	buf := make([]byte, SizeHintPubKey)
	if _, _, err := pubKey.Marshal(buf, surge.MaxBytes); err != nil {
		return nil, err
	}
	return json.Marshal(base64.RawURLEncoding.EncodeToString(buf))
}

// UnmarshalJSON implements the JSON unmarshaler interface by representing this
// private key as an unpadded base64 string.
func (pubKey *PubKey) UnmarshalJSON(data []byte) error {
	str := ""
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	buf, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	_, _, err = pubKey.Unmarshal(buf, surge.MaxBytes)
	return err
}

// PrivKey is a secp256k1 ECDSA private key.
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

// PubKey returns the ECDSA public key associated with this privey key.
func (privKey PrivKey) PubKey() *PubKey {
	return (*PubKey)(&privKey.PublicKey)
}

// Signatory returns the public identity generated from the public key
// associated with this PrivKey.
func (privKey PrivKey) Signatory() Signatory {
	return NewSignatory(privKey.PubKey())
}

// SizeHint returns the numbers of bytes required to represent this PrivKey in
// binary.
func (privKey PrivKey) SizeHint() int {
	return SizeHintPrivKey
}

// Marshal into binary.
func (privKey PrivKey) Marshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < SizeHintPrivKey || rem < SizeHintPrivKey {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}
	data := crypto.FromECDSA((*ecdsa.PrivateKey)(&privKey))
	if len(data) != SizeHintPrivKey {
		panic(fmt.Errorf("expected len=%v, got len=%v", SizeHintPrivKey, len(data)))
	}
	copy(buf, data[:])
	return buf[SizeHintPrivKey:], rem - SizeHintPrivKey, nil
}

// Unmarshal from binary.
func (privKey *PrivKey) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < SizeHintPrivKey || rem < SizeHintPrivKey {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}
	decoded, err := crypto.ToECDSA(buf[:SizeHintPrivKey])
	if err != nil {
		return buf[SizeHintPrivKey:], rem - SizeHintPrivKey, err
	}
	if decoded == nil {
		return buf[SizeHintPrivKey:], rem - SizeHintPrivKey, fmt.Errorf("decoded privkey=nil")
	}
	*privKey = (PrivKey)(*decoded)
	return buf[SizeHintPrivKey:], rem - SizeHintPrivKey, nil
}

// MarshalJSON implements the JSON marshaler interface by representing this
// private key as an unpadded base64 string.
func (privKey PrivKey) MarshalJSON() ([]byte, error) {
	buf := make([]byte, SizeHintPrivKey)
	if _, _, err := privKey.Marshal(buf, surge.MaxBytes); err != nil {
		return nil, err
	}
	return json.Marshal(base64.RawURLEncoding.EncodeToString(buf))
}

// UnmarshalJSON implements the JSON unmarshaler interface by representing this
// private key as an unpadded base64 string.
func (privKey *PrivKey) UnmarshalJSON(data []byte) error {
	str := ""
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	buf, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	_, _, err = privKey.Unmarshal(buf, surge.MaxBytes)
	return err
}
