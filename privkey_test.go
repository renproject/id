package id_test

import (
	"testing/quick"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/renproject/id"
	"github.com/renproject/surge"
)

var _ = Describe("Private keys", func() {
	Context("when signing hashes", func() {
		Context("when verifying signatures", func() {
			It("should return the expected pubkey", func() {
				f := func(data []byte) bool {
					hash := id.NewHash(data)
					privKey := id.NewPrivKey()
					sig, err := privKey.Sign(&hash)
					Expect(err).ToNot(HaveOccurred())
					expected := privKey.Signatory()
					got, err := sig.Signatory(&hash)
					Expect(err).ToNot(HaveOccurred())
					Expect(got).To(Equal(expected))
					return true
				}
				Expect(quick.Check(f, nil)).To(Succeed())
			})
		})
	})

	Context("when marshal and then unmarshaling using binary", func() {
		It("should equal itself", func() {
			f := func() bool {
				privKey := id.NewPrivKey()
				marshaled, err := surge.ToBinary(privKey)
				Expect(err).ToNot(HaveOccurred())
				unmarshaled := id.PrivKey{}
				err = surge.FromBinary(marshaled, &unmarshaled)
				Expect(err).ToNot(HaveOccurred())
				Expect(privKey.D.Cmp(unmarshaled.D)).To(Equal(0))
				Expect(privKey.X.Cmp(unmarshaled.X)).To(Equal(0))
				Expect(privKey.Y.Cmp(unmarshaled.Y)).To(Equal(0))
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})
	})

	Context("when unmarshaling random bytes using binary", func() {
		It("should equal return an error", func() {
			f := func(data []byte) bool {
				if len(data) >= 32 {
					return true
				}
				unmarshaled := id.PrivKey{}
				err := surge.FromBinary(data, &unmarshaled)
				Expect(err).To(HaveOccurred())
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})
	})
})
