package pbkdf2_test

import (
	"reflect"
	"testing"

	"github.com/aldy505/phc-crypto/pbkdf2"
)

func TestHash(t *testing.T) {
	t.Run("should be ok without additional config", func(t *testing.T) {
		hash, err := pbkdf2.Hash("password123", pbkdf2.Config{})
		if err != nil {
			t.Error(err)
		}

		typeof := reflect.TypeOf(hash).Kind()
		if typeof != reflect.String {
			t.Error("returned type is not string")
		}
	})
	t.Run("should be ok with additional config", func(t *testing.T) {
		hash, err := pbkdf2.Hash("password123", pbkdf2.Config{
			HashFunc: 10,
			Rounds:   8,
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
		hash, err := pbkdf2.Hash("password123", pbkdf2.Config{})
		if err != nil {
			t.Error(err)
		}

		verify, err := pbkdf2.Verify(hash, "password123")
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
		hash, err := pbkdf2.Hash("password123", pbkdf2.Config{})
		if err != nil {
			t.Error(err)
		}

		verify, err := pbkdf2.Verify(hash, "password321")
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

func TestSHA1(t *testing.T) {
	hash, err := pbkdf2.Hash("password123", pbkdf2.Config{
		HashFunc: pbkdf2.SHA1,
	})
	if err != nil {
		t.Error(err)
	}

	verify, err := pbkdf2.Verify(hash, "password123")
	if err != nil {
		t.Error(err)
	}
	if !verify {
		t.Error("verify function returned false")
	}
}

func TestSHA256(t *testing.T) {
	hash, err := pbkdf2.Hash("password123", pbkdf2.Config{
		HashFunc: pbkdf2.SHA256,
	})
	if err != nil {
		t.Error(err)
	}

	verify, err := pbkdf2.Verify(hash, "password123")
	if err != nil {
		t.Error(err)
	}
	if !verify {
		t.Error("verify function returned false")
	}
}

func TestSHA224(t *testing.T) {
	hash, err := pbkdf2.Hash("password123", pbkdf2.Config{
		HashFunc: pbkdf2.SHA224,
	})
	if err != nil {
		t.Error(err)
	}

	verify, err := pbkdf2.Verify(hash, "password123")
	if err != nil {
		t.Error(err)
	}
	if !verify {
		t.Error("verify function returned false")
	}
}

func TestSHA512(t *testing.T) {
	hash, err := pbkdf2.Hash("password123", pbkdf2.Config{
		HashFunc: pbkdf2.SHA512,
	})
	if err != nil {
		t.Error(err)
	}

	verify, err := pbkdf2.Verify(hash, "password123")
	if err != nil {
		t.Error(err)
	}
	if !verify {
		t.Error("verify function returned false")
	}
}

func TestSHA384(t *testing.T) {
	hash, err := pbkdf2.Hash("password123", pbkdf2.Config{
		HashFunc: pbkdf2.SHA384,
	})
	if err != nil {
		t.Error(err)
	}

	verify, err := pbkdf2.Verify(hash, "password123")
	if err != nil {
		t.Error(err)
	}
	if !verify {
		t.Error("verify function returned false")
	}
}

func TestMD5(t *testing.T) {
	hash, err := pbkdf2.Hash("password123", pbkdf2.Config{
		HashFunc: pbkdf2.MD5,
	})
	if err != nil {
		t.Error(err)
	}

	verify, err := pbkdf2.Verify(hash, "password123")
	if err != nil {
		t.Error(err)
	}
	if !verify {
		t.Error("verify function returned false")
	}
}

func TestError(t *testing.T) {
	t.Run("should return error", func(t *testing.T) {
		hashString := "$pkt$v=0$i=32$invalidSalt$invalidHash"
		_, err := pbkdf2.Verify(hashString, "something")
		if err == nil || err.Error() != "hashed string is not pbkdf2 instance" {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should fail parsing int", func(t *testing.T) {
		hashString := "$pbkdf2sha256$v=0$i=a$d172c14e9955bf4e4c01422f2af10d4f$ad21bd7d8568ce800754aafb6630e7e909006c425489778f8016d3471951d3cc"
		_, err := pbkdf2.Verify(hashString, "something")
		if err == nil {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("not supported hash function", func(t *testing.T) {
		hashString := "$pbkdf2asdf$v=0$i=4096$d172c14e9955bf4e4c01422f2af10d4f$ad21bd7d8568ce800754aafb6630e7e909006c425489778f8016d3471951d3cc"
		_, err := pbkdf2.Verify(hashString, "something")
		if err == nil || err.Error() != "invalid hash function was provided" {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should complain of empty function parameters", func(t *testing.T) {
		_, err := pbkdf2.Hash("", pbkdf2.Config{})
		if err == nil || err.Error() != "function parameters must not be empty" {
			t.Error("error should have been thrown:", err)
		}
	})

	t.Run("should complain of empty function parameters", func(t *testing.T) {
		_, err := pbkdf2.Verify("", "")
		if err == nil || err.Error() != "function parameters must not be empty" {
			t.Error("error should have been thrown:", err)
		}
	})
}
