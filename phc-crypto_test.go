package phccrypto_test

import (
	"reflect"
	"testing"

	phccrypto "github.com/aldy505/phc-crypto"
)

func TestPHCCrypto(t *testing.T) {
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
			t.Log(hash)
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
	t.Run("bcrypt test", func(t *testing.T) {
		t.Run("should be ok without additional config", func(t *testing.T) {
			crypto, err := phccrypto.Use("bcrypt", phccrypto.Config{})
			if err != nil {
				t.Error(err)
			}
			hash, err := crypto.Hash("password123")
			if err != nil {
				t.Error(err)
			}
			t.Log(hash)
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
			t.Log(hash)
			typeof := reflect.TypeOf(hash).Kind()
			if typeof != reflect.String {
				t.Error("returned type is not string")
			}
		})
	})
}
