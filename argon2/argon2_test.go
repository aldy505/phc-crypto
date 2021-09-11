package argon2_test

import (
	"reflect"
	"testing"

	"github.com/aldy505/phc-crypto/argon2"
)

func TestHash(t *testing.T) {
	t.Run("should be ok without additional config", func(t *testing.T) {
		hash, err := argon2.Hash("password123", argon2.Config{})
		if err != nil {
			t.Error(err)
		}
		typeof := reflect.TypeOf(hash).Kind()
		if typeof != reflect.String {
			t.Error("returned type is not string")
		}
	})

	t.Run("should be ok with additional config", func(t *testing.T) {
		hash, err := argon2.Hash("password123", argon2.Config{
			Parallelism: 3,
			Variant:     argon2.I,
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
		hash, err := argon2.Hash("password123", argon2.Config{})
		if err != nil {
			t.Error(err)
		}
		verify, err := argon2.Verify(hash, "password123")
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
		hash, err := argon2.Hash("password123", argon2.Config{})
		if err != nil {
			t.Error(err)
		}
		verify, err := argon2.Verify(hash, "password321")
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
