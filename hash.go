package id

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"unsafe"

	"github.com/renproject/abi"
)

// HashLength defines the length of all Hashes as 32 bytes.
const HashLength = 32

// Hash defines the output of the 256-bit SHA2 hashing function.
type Hash abi.Bytes32

// Equal compares one Hash with another.
func (hash Hash) Equal(other Hash) bool {
	return bytes.Equal(hash[:], other[:])
}

// SizeHint returns the number of bytes required to represent this Hash in
// binary.
func (hash Hash) SizeHint() int {
	return 32
}

// Marshal this Hash into binary.
func (hash Hash) Marshal(w io.Writer, m int) (int, error) {
	return abi.Bytes32(hash).Marshal(w, m)
}

// Unmarshal from binary into this Hash.
func (hash *Hash) Unmarshal(r io.Reader, m int) (int, error) {
	return (*abi.Bytes32)(hash).Unmarshal(r, m)
}

// MarshalJSON implements the JSON marshaler interface for the Hash type. It is
// represented as an unpadded base64 string.
func (hash Hash) MarshalJSON() ([]byte, error) {
	return abi.Bytes32(hash).MarshalJSON()
}

// UnmarshalJSON implements the JSON marshaler interface for the Hash type. It
// assumes that it has been represented as an unpadded base64 string.
func (hash *Hash) UnmarshalJSON(data []byte) error {
	return (*abi.Bytes32)(hash).UnmarshalJSON(data)
}

// String returns the unpadded base64 string representation of the Hash.
func (hash Hash) String() string {
	return base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
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
		for i := b; i < l; i++ {
			buf := (*[64]byte)(unsafe.Pointer(&hashes[i*2]))
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
	for i := b; i < len(hashes)/2; i++ {
		buf := [64]byte{}
		copy(buf[:32], hashes[i*2][:])
		copy(buf[32:], hashes[i*2+1][:])
		hashes[b+i] = Hash(sha256.Sum256(buf[:]))
	}
	return NewMerkleHashInPlaceSafe(hashes[:b+len(hashes)/2])
}
