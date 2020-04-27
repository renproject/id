package id_test

import (
	"encoding/json"
	"testing/quick"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/id"
)

var _ = Describe("ID", func() {
	Context("Hash", func() {
		Context("when two hashes are equal", func() {
			It("should be stringified to the same string", func() {
				test := func(hash Hash) bool {
					var newHash Hash
					copy(newHash[:], hash[:])

					Expect(hash.Equal(newHash)).Should(BeTrue())
					Expect(newHash.Equal(hash)).Should(BeTrue())
					return hash.String() == newHash.String()
				}

				Expect(quick.Check(test, nil)).Should(Succeed())
			})
		})

		Context("when two hashes are different", func() {
			It("should be stringified to different strings", func() {
				test := func() bool {
					hash1, hash2 := RandomHash(), RandomHash()

					Expect(hash1.Equal(hash2)).Should(BeFalse())
					Expect(hash2.Equal(hash1)).Should(BeFalse())
					return true
				}

				Expect(quick.Check(test, nil)).Should(Succeed())
			})
		})

		Context("when marshaling/unmarshaling", func() {
			It("should equal itself after marshaling and then unmarshaling", func() {
				test := func(hash Hash) bool {
					data, err := json.Marshal(&hash)
					Expect(err).NotTo(HaveOccurred())

					var newHash Hash
					Expect(json.Unmarshal(data, &newHash)).Should(Succeed())

					return hash.Equal(newHash)
				}

				Expect(quick.Check(test, nil)).Should(Succeed())
			})

			It("return error when trying to unmarshal incorrect data", func() {
				test := func(data []byte, array30 [30]byte) bool {
					if len(data) == HashLength {
						return true
					}
					var hash Hash
					Expect(json.Unmarshal(data, &hash)).ShouldNot(Succeed())

					data30, err := json.Marshal(array30[:])
					Expect(err).NotTo(HaveOccurred())
					Expect(json.Unmarshal(data30, &hash)).ShouldNot(Succeed())

					return true
				}

				Expect(quick.Check(test, nil)).Should(Succeed())
			})
		})
	})

	Context("Signature", func() {
		Context("when two signatures are equal", func() {
			It("should be stringified to the same string", func() {
				test := func(sig Signature) bool {
					var newSig Signature
					copy(newSig[:], sig[:])

					Expect(sig.Equal(&newSig)).Should(BeTrue())
					Expect(newSig.Equal(&sig)).Should(BeTrue())
					return sig.String() == newSig.String()
				}

				Expect(quick.Check(test, nil)).Should(Succeed())
			})
		})

		Context("when two signatures are different", func() {
			It("should return false when comparing them", func() {
				test := func() bool {
					sigs1, sigs2 := RandomSignature(), RandomSignature()
					Expect(sigs1.Equal(&sigs2)).Should(BeFalse())
					Expect(sigs2.Equal(&sigs1)).Should(BeFalse())
					return true
				}

				Expect(quick.Check(test, nil)).Should(Succeed())
			})
		})

		Context("when marshaling/unmarshaling", func() {
			It("should equal itself after marshaling and then unmarshaling", func() {
				test := func(sig Signature) bool {
					data, err := json.Marshal(sig)
					Expect(err).NotTo(HaveOccurred())

					var newSig Signature
					Expect(json.Unmarshal(data, &newSig)).Should(Succeed())

					return sig.Equal(&newSig)
				}

				Expect(quick.Check(test, nil)).Should(Succeed())
			})

			It("return error when trying to unmarshal incorrect data", func() {
				test := func(data []byte, array30 [30]byte) bool {
					if len(data) == SignatureLength {
						return true
					}
					var sig Signature
					Expect(json.Unmarshal(data, &sig)).ShouldNot(Succeed())

					data30, err := json.Marshal(array30[:])
					Expect(err).NotTo(HaveOccurred())
					Expect(json.Unmarshal(data30, &sig)).ShouldNot(Succeed())
					return true
				}

				Expect(quick.Check(test, nil)).Should(Succeed())
			})
		})
	})

	Context("Signatory", func() {
		Context("when two signatories are equal", func() {
			It("should be stringified to the same string", func() {
				test := func(sig Signatory) bool {
					var newSig Signatory
					copy(newSig[:], sig[:])

					Expect(sig.Equal(&newSig)).Should(BeTrue())
					Expect(newSig.Equal(&sig)).Should(BeTrue())
					return sig.String() == newSig.String()
				}

				Expect(quick.Check(test, nil)).Should(Succeed())
			})
		})

		Context("when two signatories are different", func() {
			It("should return false when comparing them", func() {
				test := func() bool {
					hashes1, hashes2 := RandomSignatory(), RandomSignatory()
					Expect(hashes1.Equal(&hashes2)).Should(BeFalse())
					Expect(hashes2.Equal(&hashes1)).Should(BeFalse())
					return true
				}

				Expect(quick.Check(test, nil)).Should(Succeed())
			})
		})

		Context("when marshaling/unmarshaling", func() {
			It("should equal itself after marshaling and then unmarshaling", func() {
				test := func(sig Signatory) bool {
					data, err := json.Marshal(sig)
					Expect(err).NotTo(HaveOccurred())

					var newSig Signatory
					Expect(json.Unmarshal(data, &newSig)).Should(Succeed())

					return sig.Equal(&newSig)
				}

				Expect(quick.Check(test, nil)).Should(Succeed())
			})

			It("return error when trying to unmarshal incorrect data", func() {
				test := func(data []byte, array30 [30]byte) bool {
					if len(data) == SignatoryLength {
						return true
					}
					var sig Signatory
					Expect(json.Unmarshal(data, &sig)).ShouldNot(Succeed())

					data30, err := json.Marshal(array30[:])
					Expect(err).NotTo(HaveOccurred())
					Expect(json.Unmarshal(data30, &sig)).ShouldNot(Succeed())

					return true
				}

				Expect(quick.Check(test, nil)).Should(Succeed())
			})
		})
	})
})
