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

const (
	// ROUNDS is the iteration counts.
	ROUNDS = 4096
	// KEYLEN is how many bytes to generate as output.
	KEYLEN = 32
	// DEFAULT_HASHFUNCTION is for calculating HMAC. Defaulting to sha256.
	DEFAULT_HASHFUNCTION = "sha256"
)

// Hash creates a PHC-formatted hash with config provided
func Hash(plain string, config Config) (string, error) {
	if config.Rounds == 0 {
		config.Rounds = ROUNDS
	}
	if config.KeyLen == 0 {
		config.KeyLen = KEYLEN
	}
	if config.HashFunc == "" {
		config.HashFunc = DEFAULT_HASHFUNCTION
	}

	// minimum 64 bits, 128 bits is recommended
	salt := make([]byte, 16)
	io.ReadFull(rand.Reader, salt)

	var hash []byte

	switch config.HashFunc {
	case "sha1":
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha1.New)
	case "sha256":
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha256.New)
	case "sha224":
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha256.New224)
	case "sha512":
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha512.New)
	case "sha384":
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha512.New384)
	case "md5":
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, md5.New)
	default:
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

// Verify checks the hash if it's equal (by an algorithm) to plain text provided.
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

	switch hashFunc {
	case "sha1":
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha1.New)
	case "sha256":
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha256.New)
	case "sha224":
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha256.New224)
	case "sha512":
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha512.New)
	case "sha384":
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha512.New384)
	case "md5":
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, md5.New)
	default:
		return false, errors.New("we don't support " + hashFunc + " for a hash function.")
	}

	if subtle.ConstantTimeCompare(decodedHash, verifyHash) == 1 {
		return true, nil
	}
	return false, nil
}
