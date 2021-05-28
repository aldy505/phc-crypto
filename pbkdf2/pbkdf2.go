package pbkdf2

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/aldy505/phc-crypto/format"
	"golang.org/x/crypto/pbkdf2"
)

// Config initialize the config require to create a hash function
type Config struct {
	Rounds   int
	KeyLen   int
	HashFunc string
}

func Hash(plain string, config Config) (string, error) {
	if config.Rounds == 0 {
		config.Rounds = 4096
	}
	if config.KeyLen == 0 {
		config.KeyLen = 32
	}
	if config.HashFunc == "" {
		config.HashFunc = "sha1"
	}

	salt := make([]byte, 16)
	io.ReadFull(rand.Reader, salt)

	var hash []byte

	if config.HashFunc == "sha1" {
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha1.New)
	} else if config.HashFunc == "sha256" {
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha256.New)
	} else if config.HashFunc == "sha224" {
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha256.New224)
	} else if config.HashFunc == "sha512" {
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha512.New)
	} else if config.HashFunc == "sha384" {
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha512.New384)
	} else if config.HashFunc == "md5" {
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, md5.New)
	} else {
		return "", errors.New("we don't support " + config.HashFunc + " for a hash function.")
	}

	hashString := format.Serialize(format.PHCConfig{
		ID: "pbkdf2" + config.HashFunc,
		Params: map[string]interface{}{
			"i": config.Rounds,
		},
		Salt: hex.EncodeToString(salt[:]),
		Hash: hex.EncodeToString(hash[:]),
	})

	return hashString, nil
}

func Verify(hash string, plain string) (bool, error) {
	deserialize := format.Deserialize(hash)

	if !strings.HasPrefix(deserialize.ID, "pbkdf2") {
		return false, errors.New("hashed string is not pbkdf2 instance")
	}

	decodedHash, err := hex.DecodeString(deserialize.Hash)
	if err != nil {
		return false, err
	}
	keyLen := int(len(decodedHash))

	rounds, err := strconv.ParseInt(deserialize.Params["i"].(string), 10, 32)
	if err != nil {
		return false, err
	}

	salt, err := hex.DecodeString(deserialize.Salt)
	if err != nil {
		return false, err
	}

	hashFunc := strings.Replace(deserialize.ID, "pbkdf2", "", 1)

	var verifyHash []byte

	if hashFunc == "sha1" {
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha1.New)
	} else if hashFunc == "sha256" {
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha256.New)
	} else if hashFunc == "sha224" {
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha256.New224)
	} else if hashFunc == "sha512" {
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha512.New)
	} else if hashFunc == "sha384" {
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha512.New384)
	} else if hashFunc == "md5" {
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, md5.New)
	} else {
		return false, errors.New("we don't support " + hashFunc + " for a hash function.")
	}

	if subtle.ConstantTimeCompare(decodedHash, verifyHash) == 1 {
		return true, nil
	}
	return false, nil
}
