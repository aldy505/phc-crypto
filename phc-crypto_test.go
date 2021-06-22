package phccrypto_test

import (
	"reflect"
	"testing"

	phccrypto "github.com/aldy505/phc-crypto"
)

func TestPHCCrypto_Regular(t *testing.T) {
	t.Run("setup test", func(t *testing.T) {
		t.Run("should return the same name with input", func(t *testing.T) {
			names := []string{"scrypt", "pbkdf2", "chacha20poly1305", "bcrypt", "argon2"}
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
			crypto, err := phccrypto.Use("asdf", phccrypto.Config{})
			if err.Error() != "the algorithm provided is not supported" {
				t.Error("something is wrong:", crypto.Name, "with asdf")
			}
		})
	})
	t.Run("forced not supported algorithms", func(t *testing.T) {
		t.Run("should return error on hash", func(t *testing.T) {
			crypto := &phccrypto.Algo{
				Name:   "whatever",
				Config: &phccrypto.Config{},
			}
			_, err := crypto.Hash("something")
			if err.Error() != "the algorithm provided is not supported" {
				t.Error("something is wrong:", crypto.Name, "with", err.Error())
			}
		})
		t.Run("should return error on verify", func(t *testing.T) {
			crypto := &phccrypto.Algo{
				Name:   "whatever",
				Config: &phccrypto.Config{},
			}
			_, err := crypto.Verify("something else", "something")
			if err.Error() != "the algorithm provided is not (yet) supported" {
				t.Error("something is wrong:", crypto.Name, "with", err.Error())
			}
		})
	})
}

func TestPHCCrypto_Scrypt(t *testing.T) {
	t.Run("scrypt test", func(t *testing.T) {
		t.Run("should be ok without additional config", func(t *testing.T) {
			crypto, err := phccrypto.Use("scrypt", phccrypto.Config{})
			if err != nil {
				t.Error(err)
			}
			hash, err := crypto.Hash("password123")
			if err != nil {
				t.Error(err)
			}
			typeof := reflect.TypeOf(hash).Kind()
			if typeof != reflect.String {
				t.Error("returned type is not string")
			}
		})
		t.Run("should be ok with additional config", func(t *testing.T) {
			crypto, err := phccrypto.Use("scrypt", phccrypto.Config{
				Parallelism: 3,
			})
			if err != nil {
				t.Error(err)
			}
			hash, err := crypto.Hash("password123")

			if err != nil {
				t.Error(err)
			}
			typeof := reflect.TypeOf(hash).Kind()
			if typeof != reflect.String {
				t.Error("returned type is not string")
			}
		})
		t.Run("verify should return true", func(t *testing.T) {
			crypto, err := phccrypto.Use("scrypt", phccrypto.Config{})
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
			typeof := reflect.TypeOf(verify).Kind()
			if typeof != reflect.Bool {
				t.Error("returned type is not boolean")
			}
			if !verify {
				t.Error("verify function returned false")
			}
		})
		t.Run("verify should return false", func(t *testing.T) {
			crypto, err := phccrypto.Use("scrypt", phccrypto.Config{})
			if err != nil {
				t.Error(err)
			}
			hash, err := crypto.Hash("password123")
			if err != nil {
				t.Error(err)
			}
			verify, err := crypto.Verify(hash, "password321")
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
	})
}

func TestPHCCrypto_Argon2(t *testing.T) {
	t.Run("argon2 test", func(t *testing.T) {
		t.Run("should be ok without additional config", func(t *testing.T) {
			crypto, err := phccrypto.Use("argon2", phccrypto.Config{})
			if err != nil {
				t.Error(err)
			}
			hash, err := crypto.Hash("password123")
			if err != nil {
				t.Error(err)
			}
			typeof := reflect.TypeOf(hash).Kind()
			if typeof != reflect.String {
				t.Error("returned type is not string")
			}
		})
		t.Run("should be ok with additional config", func(t *testing.T) {
			crypto, err := phccrypto.Use("argon2", phccrypto.Config{
				Parallelism: 3,
				Variant:     "i",
			})
			if err != nil {
				t.Error(err)
			}
			hash, err := crypto.Hash("password123")

			if err != nil {
				t.Error(err)
			}
			typeof := reflect.TypeOf(hash).Kind()
			if typeof != reflect.String {
				t.Error("returned type is not string")
			}
		})
		t.Run("verify should return true", func(t *testing.T) {
			crypto, err := phccrypto.Use("argon2", phccrypto.Config{})
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
			typeof := reflect.TypeOf(verify).Kind()
			if typeof != reflect.Bool {
				t.Error("returned type is not boolean")
			}
			if !verify {
				t.Error("verify function returned false")
			}
		})
		t.Run("verify should return false", func(t *testing.T) {
			crypto, err := phccrypto.Use("argon2", phccrypto.Config{})
			if err != nil {
				t.Error(err)
			}
			hash, err := crypto.Hash("password123")
			if err != nil {
				t.Error(err)
			}
			verify, err := crypto.Verify(hash, "password321")
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
	})
}

func TestPHCCrypto_Bcrypt(t *testing.T) {
	t.Run("bcrypt test", func(t *testing.T) {
		t.Run("should be ok without additional config", func(t *testing.T) {
			crypto, err := phccrypto.Use("bcrypt", phccrypto.Config{
				Rounds: 12,
			})
			if err != nil {
				t.Error(err)
			}
			hash, err := crypto.Hash("password123")

			if err != nil {
				t.Error(err)
			}
			typeof := reflect.TypeOf(hash).Kind()
			if typeof != reflect.String {
				t.Error("returned type is not string")
			}
		})
		t.Run("verify should return true", func(t *testing.T) {
			crypto, err := phccrypto.Use("bcrypt", phccrypto.Config{})
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
			typeof := reflect.TypeOf(verify).Kind()
			if typeof != reflect.Bool {
				t.Error("returned type is not boolean")
			}
			if !verify {
				t.Error("verify function returned false")
			}
		})
		t.Run("verify should return false", func(t *testing.T) {
			crypto, err := phccrypto.Use("bcrypt", phccrypto.Config{})
			if err != nil {
				t.Error(err)
			}
			hash, err := crypto.Hash("password123")
			if err != nil {
				t.Error(err)
			}
			verify, err := crypto.Verify(hash, "password321")
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
	})
}

func TestPHCCrypto_PBKDF2(t *testing.T) {
	t.Run("pbkdf2 test", func(t *testing.T) {
		t.Run("should be ok without additional config", func(t *testing.T) {
			crypto, err := phccrypto.Use("pbkdf2", phccrypto.Config{})
			if err != nil {
				t.Error(err)
			}
			hash, err := crypto.Hash("password123")
			if err != nil {
				t.Error(err)
			}
			typeof := reflect.TypeOf(hash).Kind()
			if typeof != reflect.String {
				t.Error("returned type is not string")
			}
		})
		t.Run("should be ok with additional config", func(t *testing.T) {
			crypto, err := phccrypto.Use("pbkdf2", phccrypto.Config{
				HashFunc: "sha512",
			})
			if err != nil {
				t.Error(err)
			}
			hash, err := crypto.Hash("password123")
			if err != nil {
				t.Error(err)
			}
			typeof := reflect.TypeOf(hash).Kind()
			if typeof != reflect.String {
				t.Error("returned type is not string")
			}
		})
		t.Run("verify should return true", func(t *testing.T) {
			crypto, err := phccrypto.Use("pbkdf2", phccrypto.Config{})
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
			typeof := reflect.TypeOf(verify).Kind()
			if typeof != reflect.Bool {
				t.Error("returned type is not boolean")
			}
			if !verify {
				t.Error("verify function returned false")
			}
		})
		t.Run("verify should return false", func(t *testing.T) {
			crypto, err := phccrypto.Use("pbkdf2", phccrypto.Config{})
			if err != nil {
				t.Error(err)
			}
			hash, err := crypto.Hash("password123")
			if err != nil {
				t.Error(err)
			}
			verify, err := crypto.Verify(hash, "password321")
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
	})
}

func TestPHCCrypto_Chacha20poly1305(t *testing.T) {
	t.Run("chacha20poly1305 test", func(t *testing.T) {
		t.Run("should be ok without additional config", func(t *testing.T) {
			crypto, err := phccrypto.Use("chacha20poly1305", phccrypto.Config{})
			if err != nil {
				t.Error(err)
			}
			hash, err := crypto.Hash("password123")
			if err != nil {
				t.Error(err)
			}
			typeof := reflect.TypeOf(hash).Kind()
			if typeof != reflect.String {
				t.Error("returned type is not string")
			}
		})
		t.Run("verify should return true", func(t *testing.T) {
			crypto, err := phccrypto.Use("chacha20poly1305", phccrypto.Config{})
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
			typeof := reflect.TypeOf(verify).Kind()
			if typeof != reflect.Bool {
				t.Error("returned type is not boolean")
			}
			if !verify {
				t.Error("verify function returned false")
			}
		})
		t.Run("verify should return false", func(t *testing.T) {
			crypto, err := phccrypto.Use("chacha20poly1305", phccrypto.Config{})
			if err != nil {
				t.Error(err)
			}
			hash, err := crypto.Hash("password123")
			if err != nil {
				t.Error(err)
			}
			verify, err := crypto.Verify(hash, "password321")
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
	})
}
