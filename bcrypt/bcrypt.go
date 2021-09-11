package bcrypt

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/aldy505/phc-crypto/format"
	"golang.org/x/crypto/bcrypt"
)

// Config initialize the config require to create a hash function
type Config struct {
	Rounds int
}

const (
	// ROUNDS is the cost of rounds, minimum of 4, maximum of 31.
	ROUNDS = 10
)

var ErrEmptyField error = errors.New("function parameters must not be empty")

// Hash creates a PHC-formatted hash with config provided
func Hash(plain string, config Config) (string, error) {
	if plain == "" {
		return "", ErrEmptyField
	}

	if config.Rounds == 0 {
		config.Rounds = ROUNDS
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), config.Rounds)
	if err != nil {
		return "", err
	}

	hashString := format.Serialize(format.PHCConfig{
		ID:      "bcrypt",
		Version: 0,
		Params: map[string]interface{}{
			"r": config.Rounds,
		},
		Hash: hex.EncodeToString(hash),
	})
	return hashString, nil
}

// Verify checks the hash if it's equal (by an algorithm) to plain text provided.
func Verify(hash string, plain string) (bool, error) {
	if hash == "" || plain == "" {
		return false, ErrEmptyField
	}

	deserialize := format.Deserialize(hash)
	if !strings.HasPrefix(deserialize.ID, "bcrypt") {
		return false, errors.New("hashed string is not a bcrypt instance")
	}
	decodedHash, err := hex.DecodeString(deserialize.Hash)
	if err != nil {
		return false, err
	}
	err = bcrypt.CompareHashAndPassword(decodedHash, []byte(plain))
	if err != nil {
		return false, nil
	}
	return true, nil
}
