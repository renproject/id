package id

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/renproject/surge"
)

// SizeHintHash is the number of bytes required to represent a Hash in binary.
const SizeHintHash = 32

// Hash defines the output of the 256-bit SHA2 hashing function.
type Hash [SizeHintHash]byte

// NewHash consumes a slice of bytes and hashes it using the 256-bit SHA2
// hashing function.
func NewHash(data []byte) Hash {
	return sha256.Sum256(data)
}

// Equal compares one Hash with another. If they are equal, then it returns
// true, otherwise it returns false.
func (hash Hash) Equal(other *Hash) bool {
	return bytes.Equal(hash[:], other[:])
}

// SizeHint returns the number of bytes required to represent a Hash in binary.
func (Hash) SizeHint() int {
	return SizeHintHash
}

// Marshal into binary.
func (hash Hash) Marshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < SizeHintHash || rem < SizeHintHash {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}
	copy(buf, hash[:])
	return buf[SizeHintHash:], rem - SizeHintHash, nil
}

// Unmarshal from binary.
func (hash *Hash) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < SizeHintHash || rem < SizeHintHash {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}
	copy(hash[:], buf[:SizeHintHash])
	return buf[SizeHintHash:], rem - SizeHintHash, nil
}

// MarshalJSON implements the JSON marshaler interface for the Hash type. It is
// represented as an unpadded base64 string.
func (hash Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(hash[:]))
}

// UnmarshalJSON implements the JSON unmarshaler interface for the Hash type. It
// assumes that it has been represented as an unpadded base64 string.
func (hash *Hash) UnmarshalJSON(data []byte) error {
	str := ""
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	if len(decoded) != SizeHintHash {
		return fmt.Errorf("expected len=%v, got len=%v", SizeHintHash, len(decoded))
	}
	copy(hash[:], decoded)
	return nil
}

// String returns the unpadded base64 URL string representation of the Hash.
func (hash Hash) String() string {
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// NewMerkleHash returns the root hash of the merkle tree that uses the hashes
// as leaves. The hashes are recursively hashed in pairs from left-to-right,
// with odd hashes trailing at the front. This function does not allow the
// caller to specify an arbitrary binary tree; it will always pack the hashes
// pairwise left-to-right. The input slice is unmodified.
//
// Two hashes:
//
//  /\
//
// Three hashes:
//
//   /\
//  / /\
//
// Four hashes:
//
//   /\
//  /\/\
//
// Five hashes:
//
//    /\
//   / /\
//  / /\/\
//
// Six hashes:
//
//    /\
//   / /\
//  /\/\/\
//
// Seven hashes:
//
//     /\
//    /  \
//   /\  /\
//  / /\/\/\
//
func NewMerkleHash(hashes []Hash) Hash {
	dst := make([]Hash, len(hashes))
	copy(dst, hashes)
	return NewMerkleHashInPlace(dst)
}

// NewMerkleHashInPlace returns the root hash of the merkle tree that uses the
// hashes as leaves. It is the same as NewMerkleHash but it overrides values in
// the input slice for efficiency. Only use this function if you do not need the
// input slices.
func NewMerkleHashInPlace(hashes []Hash) Hash {
	if len(hashes) == 0 {
		return Hash{}
	}
	for l := len(hashes) / 2; l >= 1; l = len(hashes) / 2 {
		b := len(hashes) & 1
		for i := 0; i < l; i++ {
			buf := (*[64]byte)(unsafe.Pointer(&hashes[b+i*2]))
			hashes[b+i] = Hash(sha256.Sum256(buf[:]))
		}
		hashes = hashes[:b+l]
	}
	return hashes[0]
}

// NewMerkleHashSafe is the same as NewMerkleHash, but it does not use any
// unsafe Go internally. This function is ~5% slower than its unsafe
// counter-part, and is primarily used to test the correctness/performance of
// the unsafe implementation.
func NewMerkleHashSafe(hashes []Hash) Hash {
	dst := make([]Hash, len(hashes))
	copy(dst, hashes)
	return NewMerkleHashInPlaceSafe(dst)
}

// NewMerkleHashInPlaceSafe is the same as NewMerkleHashInPlace, but it does not
// use any unsafe Go internally. This function is ~5% slower than its unsafe
// counter-part, and is primarily used to test the correctness/performance of
// the unsafe implementation.
func NewMerkleHashInPlaceSafe(hashes []Hash) Hash {
	// Check base cases to guarantee termination.
	switch len(hashes) {
	case 0:
		return Hash{}
	case 1:
		return hashes[0]
	case 2:
		buf := [64]byte{}
		copy(buf[:32], hashes[0][:])
		copy(buf[32:], hashes[1][:])
		return Hash(sha256.Sum256(buf[:]))
	}

	b := len(hashes) & 1
	for i := 0; i < len(hashes)/2; i++ {
		buf := [64]byte{}
		copy(buf[:32], hashes[b+i*2][:])
		copy(buf[32:], hashes[b+i*2+1][:])
		hashes[b+i] = Hash(sha256.Sum256(buf[:]))
	}
	return NewMerkleHashInPlaceSafe(hashes[:b+len(hashes)/2])
}

// NewMerkleHashFromSignatories is the same as NewMerkleHash but it accepts a
// slice of Signatories instead of a slice of Hashes.
func NewMerkleHashFromSignatories(signatories []Signatory) Hash {
	dst := make([]Signatory, len(signatories))
	copy(dst, signatories)
	return NewMerkleHashFromSignatoriesInPlace(dst)
}

// NewMerkleHashFromSignatoriesInPlace is the same as NewMerkleHashInPlace but
// it accepts a slice of Signatories instead of a slice of Hashes.
func NewMerkleHashFromSignatoriesInPlace(signatories []Signatory) Hash {
	if len(signatories) == 0 {
		return Hash{}
	}
	for l := len(signatories) / 2; l >= 1; l = len(signatories) / 2 {
		b := len(signatories) & 1
		for i := 0; i < l; i++ {
			buf := (*[64]byte)(unsafe.Pointer(&signatories[b+i*2]))
			signatories[b+i] = Signatory(sha256.Sum256(buf[:]))
		}
		signatories = signatories[:b+l]
	}
	return Hash(signatories[0])
}
