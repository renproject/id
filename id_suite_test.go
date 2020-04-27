package id_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/id"
)

func TestId(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Id Suite")
}

func RandomHash() Hash {
	hash := Hash{}
	_, err := rand.Read(hash[:])
	if err != nil {
		panic(fmt.Sprintf("cannot create random hash, err = %v", err))
	}
	return hash
}

func RandomSignature() Signature {
	signature := Signature{}
	_, err := rand.Read(signature[:])
	if err != nil {
		panic(fmt.Sprintf("cannot create random signature, err = %v", err))
	}
	return signature
}

func RandomSignatory() Signatory {
	signatory := Signatory{}
	_, err := rand.Read(signatory[:])
	if err != nil {
		panic(fmt.Sprintf("cannot create random signatory, err = %v", err))
	}
	return signatory
}
