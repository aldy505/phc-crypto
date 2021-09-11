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
		if err == nil || err.Error() != "the algorithm provided is not supported" {
			t.Error("something is wrong:", crypto.Name, "with 4")
		}
	})
}

func TestAlgoNotSupported(t *testing.T) {
	t.Run("hash", func(t *testing.T) {
		crypto := &phccrypto.Algo{
			Name:   5,
			Config: &phccrypto.Config{},
		}

		_, err := crypto.Hash("something")
		if err == nil || err.Error() != "the algorithm provided is not supported" {
			t.Error("something is wrong:", crypto.Name, "with", err.Error())
		}
	})

	t.Run("verify", func(t *testing.T) {
		crypto := &phccrypto.Algo{
			Name:   5,
			Config: &phccrypto.Config{},
		}

		_, err := crypto.Verify("something else", "something")
		if err == nil || err.Error() != "the algorithm provided is not supported" {
			t.Error("something is wrong:", crypto.Name, "with", err.Error())
		}
	})
}

func TestArgon(t *testing.T) {
	crypto, err := phccrypto.Use(phccrypto.Argon2, phccrypto.Config{})
	if err != nil {
		t.Error(err)
	}

	hash, err := crypto.Hash("password123")
	if err != nil {
		t.Error(err)
	}

	verify, err := crypto.Verify(hash, "password123")
	if err != nil {
		t.Error(err)
	}

	if !verify {
		t.Error("verify function returned false")
	}
}

func TestBcrypt(t *testing.T) {
	crypto, err := phccrypto.Use(phccrypto.Bcrypt, phccrypto.Config{})
	if err != nil {
		t.Error(err)
	}

	hash, err := crypto.Hash("password123")
	if err != nil {
		t.Error(err)
	}

	verify, err := crypto.Verify(hash, "password123")
	if err != nil {
		t.Error(err)
	}

	if !verify {
		t.Error("verify function returned false")
	}
}

func TestPbkdf2(t *testing.T) {
	crypto, err := phccrypto.Use(phccrypto.PBKDF2, phccrypto.Config{})
	if err != nil {
		t.Error(err)
	}

	hash, err := crypto.Hash("password123")
	if err != nil {
		t.Error(err)
	}

	verify, err := crypto.Verify(hash, "password123")
	if err != nil {
		t.Error(err)
	}

	if !verify {
		t.Error("verify function returned false")
	}
}

func TestScrypt(t *testing.T) {
	crypto, err := phccrypto.Use(phccrypto.Scrypt, phccrypto.Config{})
	if err != nil {
		t.Error(err)
	}

	hash, err := crypto.Hash("password123")
	if err != nil {
		t.Error(err)
	}

	verify, err := crypto.Verify(hash, "password123")
	if err != nil {
		t.Error(err)
	}

	if !verify {
		t.Error("verify function returned false")
	}
}

func TestError(t *testing.T) {
	t.Run("should complain on empty function parameters", func(t *testing.T) {
		algo := &phccrypto.Algo{}
		_, err := algo.Hash("")
		if err == nil || err.Error() != "function parameters must not be empty" {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should complain on empty function parameters", func(t *testing.T) {
		algo := &phccrypto.Algo{}
		_, err := algo.Verify("", "")
		if err == nil || err.Error() != "function parameters must not be empty" {
			t.Error("error should have been thrown:", err)
		}
	})
}
