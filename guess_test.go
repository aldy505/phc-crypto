package phccrypto_test

import (
	"testing"

	phccrypto "github.com/aldy505/phc-crypto"
)

func TestGuessVerify(t *testing.T) {
	verify, err := phccrypto.GuessVerify("something", "something")
	if err != nil {
		t.Error(err)
	}

	if !verify {
		t.Error("expected verify to be true")
	}
}