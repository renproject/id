package id_test

import (
	"crypto/rand"
	"fmt"
	mRand "math/rand"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/id"
)

func TestId(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Id Suite")
}

func init() {
	mRand.Seed(time.Now().Unix())
}

func RandomHash() Hash {
	hash := Hash{}
	_, err := rand.Read(hash[:])
	if err != nil {
		panic(fmt.Sprintf("cannot create random hash, err = %v", err))
	}
	return hash
}

func RandomHashes() Hashes {
	length := mRand.Intn(30)
	hashes := make(Hashes, length)
	for i := 0; i < length; i++ {
		_, err := rand.Read(hashes[i][:])
		if err != nil {
			panic(fmt.Sprintf("cannot create random hash, err = %v", err))
		}
	}
	return hashes
}

func RandomSignature() Signature {
	signature := Signature{}
	_, err := rand.Read(signature[:])
	if err != nil {
		panic(fmt.Sprintf("cannot create random signature, err = %v", err))
	}
	return signature
}

func RandomSignatures() Signatures {
	length := mRand.Intn(30)
	sigs := make(Signatures, length)
	for i := 0; i < length; i++ {
		_, err := rand.Read(sigs[i][:])
		if err != nil {
			panic(fmt.Sprintf("cannot create random signature, err = %v", err))
		}
	}
	return sigs
}

func RandomSignatory() Signatory {
	signatory := Signatory{}
	_, err := rand.Read(signatory[:])
	if err != nil {
		panic(fmt.Sprintf("cannot create random signatory, err = %v", err))
	}
	return signatory
}

func RandomSignatories() Signatories {
	length := mRand.Intn(30)
	sigs := make(Signatories, length)
	for i := 0; i < length; i++ {
		_, err := rand.Read(sigs[i][:])
		if err != nil {
			panic(fmt.Sprintf("cannot create random signatory, err = %v", err))
		}
	}
	return sigs
}
