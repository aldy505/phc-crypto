package scrypt_test

import (
	"reflect"
	"testing"

	"github.com/aldy505/phc-crypto/scrypt"
)

func TestHash(t *testing.T) {
	t.Run("should be ok without additional config", func(t *testing.T) {
		hash, err := scrypt.Hash("password123", scrypt.Config{})
		if err != nil {
			t.Error(err)
		}

		typeof := reflect.TypeOf(hash).Kind()
		if typeof != reflect.String {
			t.Error("returned type is not string")
		}
	})

	t.Run("should be ok with additional config", func(t *testing.T) {
		hash, err := scrypt.Hash("password123", scrypt.Config{
			Parallelism: 3,
		})
		if err != nil {
			t.Error(err)
		}

		typeof := reflect.TypeOf(hash).Kind()
		if typeof != reflect.String {
			t.Error("returned type is not string")
		}
	})
}

func TestVerify(t *testing.T) {
	t.Run("verify should return true", func(t *testing.T) {
		hash, err := scrypt.Hash("password123", scrypt.Config{})
		if err != nil {
			t.Error(err)
		}

		verify, err := scrypt.Verify(hash, "password123")
		if err != nil {
			t.Error(err)
		}

		typeof := reflect.TypeOf(verify).Kind()
		if typeof != reflect.Bool {
			t.Error("returned type is not boolean")
		}

		if !verify {
			t.Error("verify function returned false")
		}
	})

	t.Run("verify should return false", func(t *testing.T) {
		hash, err := scrypt.Hash("password123", scrypt.Config{})
		if err != nil {
			t.Error(err)
		}

		verify, err := scrypt.Verify(hash, "password321")
		if err != nil {
			t.Error(err)
		}

		typeof := reflect.TypeOf(verify).Kind()
		if typeof != reflect.Bool {
			t.Error("returned type is not boolean")
		}

		if verify {
			t.Error("verify function returned false")
		}
	})
}

func TestError(t *testing.T) {
	t.Run("should return error", func(t *testing.T) {
		hashString := "$str$v=0$ln=100,r=8,p=2$invalidSalt$invalidHash"
		_, err := scrypt.Verify(hashString, "something")
		if err == nil || err.Error() != "hashed string is not scrypt instance" {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should complain on empty function parameters", func(t *testing.T) {
		_, err := scrypt.Hash("", scrypt.Config{})
		if err == nil || err.Error() != "function parameters must not be empty" {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should complain on empty function parameters", func(t *testing.T) {
		_, err := scrypt.Verify("", "")
		if err == nil || err.Error() != "function parameters must not be empty" {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail decoding hex string - hash", func(t *testing.T) {
		hashString := "$scrypt$v=0$ln=100,r=8,p=2$invalidSalt$invalidHash"
		_, err := scrypt.Verify(hashString, "something")
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail decoding hex string - hash", func(t *testing.T) {
		hashString := "$scrypt$v=0$ln=100,r=8,p=2$invalidSalt$59ddeb9a31a64685314c9c58415088dc22c088bd11fe6f55ce3b55bdb1feab3d"
		_, err := scrypt.Verify(hashString, "something")
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail parsing int - 1", func(t *testing.T) {
		hashString := "$scrypt$v=0$ln=a,r=8,p=2$e845024f7c76d010080e49f31838d0e1$59ddeb9a31a64685314c9c58415088dc22c088bd11fe6f55ce3b55bdb1feab3d"
		_, err := scrypt.Verify(hashString, "something")
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail parsing int - 2", func(t *testing.T) {
		hashString := "$scrypt$v=0$ln=100,r=a,p=2$e845024f7c76d010080e49f31838d0e1$59ddeb9a31a64685314c9c58415088dc22c088bd11fe6f55ce3b55bdb1feab3d"
		_, err := scrypt.Verify(hashString, "something")
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail parsing int - 3", func(t *testing.T) {
		hashString := "$scrypt$v=0$ln=100,r=8,p=a$e845024f7c76d010080e49f31838d0e1$59ddeb9a31a64685314c9c58415088dc22c088bd11fe6f55ce3b55bdb1feab3d"
		_, err := scrypt.Verify(hashString, "something")
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})
}
