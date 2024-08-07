package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
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
	SaltLen     int
	Variant     Variant
}

// Variant sets up enum for available Argon2 variants
type Variant int

const (
	// ID points to Argon2 id variant
	ID Variant = iota
	// I points to Argon2 i variant
	I
)

const (
	// KEY_LENGTH is the desired number of returned bytes
	KEY_LENGTH = 64
	// TIME is the number of iterations to perform
	TIME = 16
	// MEMORY is the a mount of memory (in kilobytes) to use
	MEMORY = 64 * 1024
	// PARALLELISM is the degree of parallelism (i.e. number of threads)
	PARALLELISM = 4
	// DEFAULT_VARIANT combines the Argon2d and Argon2i
	DEFAULT_VARIANT = ID
	// SALT_LENGTH is the default salth length in bytes.
	SALT_LENGTH = 32
)

var ErrEmptyField error = errors.New("function parameters must not be empty")

// Hash creates a PHC-formatted hash with config provided
//
//	package main
//
//	import (
//		"fmt"
//		"github.com/aldy505/phc-crypto/argon2"
//	)
//
//	func main() {
//		hash, err := argon2.Hash("password", argon2.Config{
//			Parallelism: 3,
//			Variant: argon2.I,
//		})
//		if err != nil {
//			fmt.Println(err)
//		}
//		fmt.Println(hash) // $argon2i$v=19$m=65536,t=16,p=3$8400b4e5f01f30092b794de34c61a6fdfea6b6b446560fda08a876bd11e9c62e$3fd77927d189...
//	}
func Hash(plain string, config Config) (string, error) {
	if plain == "" {
		return "", ErrEmptyField
	}

	if config.KeyLen <= 0 {
		config.KeyLen = KEY_LENGTH
	}
	if config.Time <= 0 {
		config.Time = TIME
	}
	if config.Memory <= 0 {
		config.Memory = MEMORY
	}
	if config.Parallelism <= 0 {
		config.Parallelism = PARALLELISM
	}
	if config.Variant < 0 || config.Variant > 1 {
		config.Variant = DEFAULT_VARIANT
	}
	if config.SaltLen <= 0 {
		config.SaltLen = SALT_LENGTH
	}

	// random-generated salt (16 bytes recommended for password hashing)
	salt := make([]byte, config.SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("reading random reader: %w", err)
	}

	var hash []byte
	if config.Variant == ID {
		hash = argon2.IDKey([]byte(plain), salt, uint32(config.Time), uint32(config.Memory), uint8(config.Parallelism), uint32(config.KeyLen))
	} else if config.Variant == I {
		hash = argon2.Key([]byte(plain), salt, uint32(config.Time), uint32(config.Memory), uint8(config.Parallelism), uint32(config.KeyLen))
	}
	version := argon2.Version
	hashString := format.Serialize(format.PHCConfig{
		ID:      "argon2" + returnVariant(config.Variant),
		Version: version,
		Params: map[string]interface{}{
			"m": int(config.Memory),
			"t": int(config.Time),
			"p": int(config.Parallelism),
		},
		Salt: salt,
		Hash: hash,
	})
	return hashString, nil
}

// Verify checks the hash if it's equal (by an algorithm) to plain text provided.
//
//	package main
//
//	import (
//	  "fmt"
//	  "github.com/aldy505/phc-crypto/argon2"
//	)
//
//	func main() {
//	  hash := "$argon2i$v=19$m=65536,t=16,p=3$8400b4e5f01f30092b794de34c61a6fdfea6b6b446560fda08a876bd11e9c62e$3fd77927d189..."
//
//	  verify, err := argon2.Verify(hash, "password")
//	  if err != nil {
//	    fmt.Println(err)
//	  }
//	  fmt.Println(verify) // true
//	}
func Verify(hash string, plain string) (bool, error) {
	if hash == "" || plain == "" {
		return false, ErrEmptyField
	}

	deserialize, err := format.Deserialize(hash)
	if err != nil {
		return false, err
	}

	if !strings.HasPrefix(deserialize.ID, "argon2") {
		return false, errors.New("hashed string is not argon instance")
	}

	keyLen := uint32(len(deserialize.Hash))

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

	var verifyHash []byte
	if deserialize.ID == "argon2id" {
		verifyHash = argon2.IDKey([]byte(plain), deserialize.Salt, uint32(time), uint32(memory), uint8(parallelism), keyLen)
	} else if deserialize.ID == "argon2i" {
		verifyHash = argon2.Key([]byte(plain), deserialize.Salt, uint32(time), uint32(memory), uint8(parallelism), keyLen)
	}

	if subtle.ConstantTimeCompare(verifyHash, deserialize.Hash) == 1 {
		return true, nil
	}
	return false, nil
}

// returnVariant converts enum variant to string for serializing hash
func returnVariant(variant Variant) string {
	if variant == ID {
		return "id"
	} else if variant == I {
		return "i"
	}
	return ""
}
