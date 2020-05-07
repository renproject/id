package id_test

import (
	"bytes"
	"encoding/json"
	"testing/quick"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/renproject/id"
	"github.com/renproject/surge"
)

var _ = Describe("Signatures", func() {
	Context("when marshaling and then unmarshaling using binary", func() {
		It("should equal itself", func() {
			f := func(data [65]byte) bool {
				sig := id.Signature(data)
				marshaled, err := surge.ToBinary(sig)
				Expect(err).ToNot(HaveOccurred())
				unmarshaled := id.Signature{}
				err = surge.FromBinary(marshaled, &unmarshaled)
				Expect(err).ToNot(HaveOccurred())
				Expect(sig.Equal(&unmarshaled)).To(BeTrue())
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})
	})

	Context("when unmarshaling random bytes using binary", func() {
		It("should equal reutrn an error", func() {
			f := func(data []byte) bool {
				if len(data) >= 65 {
					return true
				}
				unmarshaled := id.Signature{}
				err := surge.FromBinary(data, &unmarshaled)
				Expect(err).To(HaveOccurred())
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})
	})

	Context("when marshaling and then unmarshaling using JSON", func() {
		It("should equal itself", func() {
			f := func(data [65]byte) bool {
				sig := id.Signature(data)
				marshaled, err := sig.MarshalJSON()
				Expect(err).ToNot(HaveOccurred())
				unmarshaled := id.Signature{}
				err = unmarshaled.UnmarshalJSON(marshaled)
				Expect(err).ToNot(HaveOccurred())
				Expect(sig.Equal(&unmarshaled)).To(BeTrue())
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})

		It("should equal its string representation", func() {
			f := func(data [65]byte) bool {
				sig := id.Signature(data)
				got, err := sig.MarshalJSON()
				Expect(err).ToNot(HaveOccurred())
				expected, err := json.Marshal(sig.String())
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
				unmarshaled := id.Signature{}
				err := unmarshaled.UnmarshalJSON(data)
				Expect(err).To(HaveOccurred())
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})
	})
})

var _ = Describe("Signatories", func() {
	Context("when marshaling and then unmarshaling using binary", func() {
		It("should equal itself", func() {
			f := func(data [32]byte) bool {
				sig := id.Signatory(data)
				marshaled, err := surge.ToBinary(sig)
				Expect(err).ToNot(HaveOccurred())
				unmarshaled := id.Signatory{}
				err = surge.FromBinary(marshaled, &unmarshaled)
				Expect(err).ToNot(HaveOccurred())
				Expect(sig.Equal(&unmarshaled)).To(BeTrue())
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
				unmarshaled := id.Signatory{}
				err := surge.FromBinary(data, &unmarshaled)
				Expect(err).To(HaveOccurred())
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})
	})

	Context("when marshaling and then unmarshaling using JSON", func() {
		It("should equal itself", func() {
			f := func(data [32]byte) bool {
				sig := id.Signatory(data)
				marshaled, err := sig.MarshalJSON()
				Expect(err).ToNot(HaveOccurred())
				unmarshaled := id.Signatory{}
				err = unmarshaled.UnmarshalJSON(marshaled)
				Expect(err).ToNot(HaveOccurred())
				Expect(sig.Equal(&unmarshaled)).To(BeTrue())
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})

		It("should equal its string representation", func() {
			f := func(data [32]byte) bool {
				sig := id.Signatory(data)
				got, err := sig.MarshalJSON()
				Expect(err).ToNot(HaveOccurred())
				expected, err := json.Marshal(sig.String())
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
				unmarshaled := id.Signatory{}
				err := unmarshaled.UnmarshalJSON(data)
				Expect(err).To(HaveOccurred())
				return true
			}
			Expect(quick.Check(f, nil)).To(Succeed())
		})
	})
})
