package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/aldy505/phc-crypto/format"
	"golang.org/x/crypto/argon2"
)

// Config initialize the config require to create a hash function
type Config struct {
	Time        int
	Memory      int
	Parallelism int
	KeyLen      int
	Variant     string
}

const (
	// Desired number of returned bytes
	KEYLEN = 64
	// Number of iterations to perform
	TIME = 16
	// Amount of memory (in kilobytes) to use
	MEMORY = 64 * 1024
	// Degree of parallelism (i.e. number of threads)
	PARALLELISM = 4
	// Combines the Argon2d and Argon2i
	DEFAULT_VARIANT = "id"
)

// Hash creates a PHC-formatted hash with config provided
func Hash(plain string, config Config) (string, error) {
	if config.KeyLen == 0 {
		config.KeyLen = KEYLEN
	}
	if config.Time == 0 {
		config.Time = TIME
	}
	if config.Memory == 0 {
		config.Memory = MEMORY
	}
	if config.Parallelism == 0 {
		config.Parallelism = PARALLELISM
	}
	if config.Variant == "" {
		config.Variant = DEFAULT_VARIANT
	}

	// random-generated salt (16 bytes recommended for password hashing)
	salt := make([]byte, 32)
	io.ReadFull(rand.Reader, salt)

	var hash []byte
	if config.Variant == "id" {
		hash = argon2.IDKey([]byte(plain), salt, uint32(config.Time), uint32(config.Memory), uint8(config.Parallelism), uint32(config.KeyLen))
	} else if config.Variant == "i" {
		hash = argon2.Key([]byte(plain), salt, uint32(config.Time), uint32(config.Memory), uint8(config.Parallelism), uint32(config.KeyLen))
	}
	version := argon2.Version
	hashString := format.Serialize(format.PHCConfig{
		ID:      "argon2" + config.Variant,
		Version: version,
		Params: map[string]interface{}{
			"m": int(config.Memory),
			"t": int(config.Time),
			"p": int(config.Parallelism),
		},
		Salt: hex.EncodeToString(salt),
		Hash: hex.EncodeToString(hash),
	})
	return hashString, nil
}

// Verify checks the hash if it's equal (by an algorithm) to plain text provided.
func Verify(hash string, plain string) (bool, error) {
	deserialize := format.Deserialize(hash)
	if !strings.HasPrefix(deserialize.ID, "argon2") {
		return false, errors.New("hashed string is not argon instance")
	}

	var verifyHash []byte
	decodedHash, err := hex.DecodeString(deserialize.Hash)
	if err != nil {
		return false, err
	}
	keyLen := uint32(len(decodedHash))

	time, err := strconv.ParseUint(deserialize.Params["t"].(string), 10, 32)
	if err != nil {
		return false, err
	}
	memory, err := strconv.ParseUint(deserialize.Params["m"].(string), 10, 32)
	if err != nil {
		return false, err
	}
	parallelism, err := strconv.ParseUint(deserialize.Params["p"].(string), 10, 32)
	if err != nil {
		return false, err
	}

	salt, err := hex.DecodeString(deserialize.Salt)
	if err != nil {
		return false, err
	}

	if deserialize.ID == "argon2id" {
		verifyHash = argon2.IDKey([]byte(plain), salt, uint32(time), uint32(memory), uint8(parallelism), keyLen)
	} else if deserialize.ID == "argon2i" {
		verifyHash = argon2.Key([]byte(plain), salt, uint32(time), uint32(memory), uint8(parallelism), keyLen)
	}

	if subtle.ConstantTimeCompare(verifyHash, decodedHash) == 1 {
		return true, nil
	}
	return false, nil
}
