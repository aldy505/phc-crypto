package argon2_test

import (
	"reflect"
	"testing"

	"github.com/aldy505/phc-crypto/argon2"
)

func TestHash(t *testing.T) {
	t.Run("should be ok without additional config", func(t *testing.T) {
		hash, err := argon2.Hash("password123", argon2.Config{
			Variant: 2,
		})
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
	t.Run("verify should return true - argon2id", func(t *testing.T) {
		hash, err := argon2.Hash("password123", argon2.Config{
			Variant: argon2.ID,
		})
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

	t.Run("verify should return true - argon2i", func(t *testing.T) {
		hash, err := argon2.Hash("password123", argon2.Config{
			Variant: argon2.I,
		})
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

func TestError(t *testing.T) {
	t.Run("should return error", func(t *testing.T) {
		hashString := "$argon3$v=2$t=16,m=64,p=32$invalidSalt$invalidHash"
		_, err := argon2.Verify(hashString, "something")
		if err == nil || err.Error() != "hashed string is not argon instance" {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail parsing int - 1", func(t *testing.T) {
		hashString := "$argon2id$v=2$t=a,m=64,p=32$kza7VOj1UyzB8wUCYtkLjSwM3KATIahmHF6NpkF5gZk$yeDXRKyv5d3LhElCp1uG1ch402VtTOF/XDDDsxoRe0H9l4Wx36R8efb4aErKrXBVqWS6mbvIzyJb/kBbrCLV0g"
		_, err := argon2.Verify(hashString, "something")
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail parsing int - 2", func(t *testing.T) {
		hashString := "$argon2id$v=2$t=16,m=a,p=32$kza7VOj1UyzB8wUCYtkLjSwM3KATIahmHF6NpkF5gZk$yeDXRKyv5d3LhElCp1uG1ch402VtTOF/XDDDsxoRe0H9l4Wx36R8efb4aErKrXBVqWS6mbvIzyJb/kBbrCLV0g"
		_, err := argon2.Verify(hashString, "something")
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail parsing int - 3", func(t *testing.T) {
		hashString := "$argon2id$v=2$t=16,m=64,p=a$9336bb54e8f5532cc1f3050262d90b8d2c0cdca01321a8661c5e8da64179819$yeDXRKyv5d3LhElCp1uG1ch402VtTOF/XDDDsxoRe0H9l4Wx36R8efb4aErKrXBVqWS6mbvIzyJb/kBbrCLV0g"
		_, err := argon2.Verify(hashString, "something")
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should complain of empty function parameters", func(t *testing.T) {
		_, err := argon2.Hash("", argon2.Config{})
		if err == nil || err.Error() != "function parameters must not be empty" {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should complain of empty function parameters", func(t *testing.T) {
		_, err := argon2.Verify("", "")
		if err == nil || err.Error() != "function parameters must not be empty" {
			t.Error("error should have been thrown:", err)
		}
	})
}
