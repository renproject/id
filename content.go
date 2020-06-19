package id

import "github.com/renproject/surge"

// Content defines an interface for hash-addressable data. Content must be able
// to represent itself in binary, and must expose a way to acquire a unique hash
// to itself. Typically, the hash will be the SHA2 256-bit hash of the binary
// representation of the content. However, this is not strictly required, and
// should not be assumed.
type Content interface {
	surge.Marshaler

	// Hash of the Content. It must be unique with respect to the content, but
	// it does not necessarily have to be a hash of the content.
	Hash() (Hash, error)
}

// A Blob is a helper type for hash-addressable content where the hash is known
// to be the SHA2 256-bit hash of the binary representation of the content.
type Blob struct {
	inner surge.Marshaler
}

// NewBlob returns a wrapper around a type that knows how to represent itself in
// binary.
func NewBlob(blob surge.Marshaler) Blob {
	return Blob{inner: blob}
}

// SizeHint returns the number of bytes required to represent the blob in
// binary. This returns the same number as the inner content used to create the
// blob.
func (blob Blob) SizeHint() int {
	return blob.inner.SizeHint()
}

// Marshal to binary. This is the same as marshaling the inner content used to
// create the blob.
func (blob Blob) Marshal(buf []byte, rem int) ([]byte, int, error) {
	return blob.inner.Marshal(buf, rem)
}

// Hash returns the SHA2 256-bit hash of the inner content used to create the
// blob.
func (blob Blob) Hash() (Hash, error) {
	buf := make([]byte, blob.SizeHint())
	_, _, err := blob.Marshal(buf, surge.MaxBytes)
	if err != nil {
		return Hash{}, err
	}
	return NewHash(buf), nil
}
