package bcrypt_test

import (
	"reflect"
	"testing"

	"github.com/aldy505/phc-crypto/bcrypt"
)

func TestHash(t *testing.T) {
	t.Run("should be ok without additional config", func(t *testing.T) {
		hash, err := bcrypt.Hash("password123", bcrypt.Config{})
		if err != nil {
			t.Error(err)
		}

		typeof := reflect.TypeOf(hash).Kind()
		if typeof != reflect.String {
			t.Error("returned type is not string")
		}
	})

	t.Run("should be ok with additional config", func(t *testing.T) {
		hash, err := bcrypt.Hash("password123", bcrypt.Config{
			Rounds: 12,
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
		hash, err := bcrypt.Hash("password123", bcrypt.Config{})
		if err != nil {
			t.Error(err)
		}

		verify, err := bcrypt.Verify(hash, "password123")
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
		hash, err := bcrypt.Hash("password123", bcrypt.Config{})
		if err != nil {
			t.Error(err)
		}

		verify, err := bcrypt.Verify(hash, "password321")
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
		hashString := "$bct$v=0$r=32$invalidSalt$invalidHash"
		_, err := bcrypt.Verify(hashString, "something")
		if err == nil || err.Error() != "hashed string is not a bcrypt instance" {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should complain of empty function parameters", func(t *testing.T) {
		_, err := bcrypt.Hash("", bcrypt.Config{})
		if err == nil || err.Error() != "function parameters must not be empty" {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should complain of empty function parameters", func(t *testing.T) {
		_, err := bcrypt.Verify("", "")
		if err == nil || err.Error() != "function parameters must not be empty" {
			t.Error("error should have been thrown:", err)
		}
	})
}
