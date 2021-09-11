package phccrypto_test

import (
	"testing"

	phccrypto "github.com/aldy505/phc-crypto"
)

func TestUse(t *testing.T) {
	t.Run("should return the same name with input", func(t *testing.T) {
		names := []phccrypto.Algorithm{phccrypto.Scrypt, phccrypto.Argon2, phccrypto.Bcrypt, phccrypto.PBKDF2}

		for i := range names {
			crypto, err := phccrypto.Use(names[i], phccrypto.Config{})
			if err != nil {
				t.Error(err)
			}

			if crypto.Name != names[i] {
				t.Error("name mismatch:", crypto.Name, "with", names[i])
			}
		}
	})
	
	t.Run("should return error because of name mismatch", func(t *testing.T) {
		crypto, _ := phccrypto.Use(4, phccrypto.Config{})

		_, err := crypto.Hash("not so shabby")
		if err.Error() != "the algorithm provided is not supported" {
			t.Error("something is wrong:", crypto.Name, "with 4")
		}
	})
}

func TestHash(t *testing.T) {
	t.Run("forced not supported algorithms", func(t *testing.T) {
		t.Run("should return error on hash", func(t *testing.T) {
			crypto := &phccrypto.Algo{
				Name:   5,
				Config: &phccrypto.Config{},
			}

			_, err := crypto.Hash("something")
			if err.Error() != "the algorithm provided is not supported" {
				t.Error("something is wrong:", crypto.Name, "with", err.Error())
			}
		})
		
		t.Run("should return error on verify", func(t *testing.T) {
			crypto := &phccrypto.Algo{
				Name:   5,
				Config: &phccrypto.Config{},
			}

			_, err := crypto.Verify("something else", "something")
			if err.Error() != "the algorithm provided is not (yet) supported" {
				t.Error("something is wrong:", crypto.Name, "with", err.Error())
			}
		})
	})
}
