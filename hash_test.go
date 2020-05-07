package id_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"testing/quick"

	"github.com/renproject/id"
	"github.com/renproject/surge"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Hashes", func() {
	Context("when hashing data", func() {
		It("should return the SHA2 256-bit hash of the data", func() {
			f := func(data []byte) bool {
				expected := id.Hash(sha256.Sum256(data))
				got := id.NewHash(data)
				Expect(got.Equal(&expected)).To(BeTrue())
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})
	})

	Context("when marshaling and then unmarshaling using binary", func() {
		It("should equal itself", func() {
			f := func(data []byte) bool {
				hash := id.NewHash(data)
				marshaled, err := surge.ToBinary(hash)
				Expect(err).ToNot(HaveOccurred())
				unmarshaled := id.Hash{}
				err = surge.FromBinary(marshaled, &unmarshaled)
				Expect(err).ToNot(HaveOccurred())
				Expect(hash.Equal(&unmarshaled)).To(BeTrue())
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})
	})

	Context("when unmarshaling random bytes using binary", func() {
		It("should equal reutrn an error", func() {
			f := func(data []byte) bool {
				if len(data) >= 32 {
					return true
				}
				unmarshaled := id.Hash{}
				err := surge.FromBinary(data, &unmarshaled)
				Expect(err).To(HaveOccurred())
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})
	})

	Context("when marshaling and then unmarshaling using JSON", func() {
		It("should equal itself", func() {
			f := func(data []byte) bool {
				hash := id.NewHash(data)
				marshaled, err := hash.MarshalJSON()
				Expect(err).ToNot(HaveOccurred())
				unmarshaled := id.Hash{}
				err = unmarshaled.UnmarshalJSON(marshaled)
				Expect(err).ToNot(HaveOccurred())
				Expect(hash.Equal(&unmarshaled)).To(BeTrue())
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})

		It("should equal its string representation", func() {
			f := func(data []byte) bool {
				hash := id.NewHash(data)
				got, err := hash.MarshalJSON()
				Expect(err).ToNot(HaveOccurred())
				expected, err := json.Marshal(hash.String())
				Expect(err).ToNot(HaveOccurred())
				Expect(bytes.Equal(got, expected)).To(BeTrue())
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})
	})

	Context("when unmarshaling random bytes using JSON", func() {
		It("should equal reutrn an error", func() {
			f := func(data []byte) bool {
				unmarshaled := id.Hash{}
				err := unmarshaled.UnmarshalJSON(data)
				Expect(err).To(HaveOccurred())
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})
	})

	Context("when computing the merkle hash", func() {
		Context("when using the safe and unsafe implementations", func() {
			Context("when computing the merkle hash of zero hashes", func() {
				It("should return the empty hash", func() {
					f := func() bool {
						hashes := make([]id.Hash, 0)
						rootHash := id.NewMerkleHash(hashes)
						safeRootHash := id.NewMerkleHashSafe(hashes)
						Expect(rootHash).To(Equal(id.Hash{}))
						Expect(safeRootHash).To(Equal(id.Hash{}))
						return true
					}
					Expect(quick.Check(f, nil)).To(Succeed())
				})
			})

			Context("when computing the merkle hash of one hash", func() {
				It("should return the input hash", func() {
					f := func() bool {
						hashes := make([]id.Hash, 1)
						for i := range hashes {
							rand.Read(hashes[i][:])
						}
						rootHash := id.NewMerkleHash(hashes)
						safeRootHash := id.NewMerkleHashSafe(hashes)
						Expect(rootHash).To(Equal(hashes[0]))
						Expect(safeRootHash).To(Equal(hashes[0]))
						return true
					}
					Expect(quick.Check(f, nil)).To(Succeed())
				})
			})

			Context("when computing the merkle hash of two hashes", func() {
				It("should return the same merkle hash", func() {
					f := func() bool {
						hashes := make([]id.Hash, 2)
						for i := range hashes {
							rand.Read(hashes[i][:])
						}
						expectedHash := id.Hash(sha256.Sum256(append(hashes[0][:], hashes[1][:]...)))
						rootHash := id.NewMerkleHash(hashes)
						safeRootHash := id.NewMerkleHashSafe(hashes)
						Expect(rootHash).To(Equal(expectedHash))
						Expect(safeRootHash).To(Equal(expectedHash))
						return true
					}
					Expect(quick.Check(f, nil)).To(Succeed())
				})
			})

			Context("when computing the merkle hash of three hash", func() {
				It("should return the same merkle hash", func() {
					f := func() bool {
						hashes := make([]id.Hash, 3)
						for i := range hashes {
							rand.Read(hashes[i][:])
						}
						expectedHash := id.Hash(sha256.Sum256(append(hashes[1][:], hashes[2][:]...)))
						expectedHash = id.Hash(sha256.Sum256(append(hashes[0][:], expectedHash[:]...)))
						rootHash := id.NewMerkleHash(hashes)
						safeRootHash := id.NewMerkleHashSafe(hashes)
						Expect(rootHash).To(Equal(expectedHash))
						Expect(safeRootHash).To(Equal(expectedHash))
						return true
					}
					Expect(quick.Check(f, nil)).To(Succeed())
				})
			})

			It("should return the same merkle hash", func() {
				f := func(n uint) bool {
					n = n % 1000
					hashes := make([]id.Hash, n)
					for i := range hashes {
						rand.Read(hashes[i][:])
					}
					rootHash := id.NewMerkleHash(hashes)
					safeRootHash := id.NewMerkleHashSafe(hashes)
					Expect(rootHash).To(Equal(safeRootHash))
					return true
				}
				Expect(quick.Check(f, nil)).To(Succeed())
			})
		})

		Context("when using signatories", func() {
			It("should equal the hash equivalent", func() {
				f := func(n uint) bool {
					n = n % 1000
					hashes := make([]id.Hash, n)
					for i := range hashes {
						rand.Read(hashes[i][:])
					}
					signatories := make([]id.Signatory, n)
					for i := range signatories {
						signatories[i] = id.Signatory(hashes[i])
					}
					expected := id.NewMerkleHash(hashes)
					got := id.NewMerkleHashFromSignatories(signatories)
					Expect(expected).To(Equal(got))
					return true
				}
				Expect(quick.Check(f, nil)).To(Succeed())
			})
		})
	})
})

func BenchmarkMerkleHash(b *testing.B) {
	hashes := make([]id.Hash, b.N)
	for i := range hashes {
		rand.Read(hashes[i][:])
	}
	b.ResetTimer()
	b.ReportAllocs()
	id.NewMerkleHash(hashes)
}

func BenchmarkMerkleHashSafe(b *testing.B) {
	hashes := make([]id.Hash, b.N)
	for i := range hashes {
		rand.Read(hashes[i][:])
	}
	b.ResetTimer()
	b.ReportAllocs()
	id.NewMerkleHashSafe(hashes)
}

func BenchmarkMerkleHash1000(b *testing.B) {
	hashes := make([]id.Hash, 1000)
	for i := range hashes {
		rand.Read(hashes[i][:])
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		id.NewMerkleHash(hashes)
	}
}

func BenchmarkMerkleHashSafe1000(b *testing.B) {
	hashes := make([]id.Hash, 1000)
	for i := range hashes {
		rand.Read(hashes[i][:])
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		id.NewMerkleHashSafe(hashes)
	}
}
