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

func Hash(plain string, config Config) (string, error) {
	if config.Rounds == 0 {
		config.Rounds = 10
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), config.Rounds)
	hashString := format.Serialize(format.PHCConfig{
		ID:      "bcrypt",
		Version: 0,
		Params: map[string]interface{}{
			"r": config.Rounds,
		},
		Hash: hex.EncodeToString(hash),
	})
	if err != nil {
		return "", err
	}
	return hashString, nil
}

func Verify(hash string, plain string) (bool, error) {
	deserialize := format.Deserialize(hash)
	if !strings.HasPrefix(deserialize.ID, "bcrypt") {
		return false, errors.New("hashed string is not a bcrypt instance")
	}
	decodedHash, err := hex.DecodeString(deserialize.Hash)
	if err != nil {
		return false, nil
	}
	err = bcrypt.CompareHashAndPassword(decodedHash, []byte(plain))
	if err != nil {
		return false, nil
	}
	return true, nil
}
