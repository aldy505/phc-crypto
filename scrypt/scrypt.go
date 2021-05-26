package scrypt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/aldy505/phc-crypto/format"
	"golang.org/x/crypto/scrypt"
)

// Config initialize the config require to create a hash function
type Config struct {
	Cost        int
	Rounds      int
	Parallelism int
	KeyLen      int
}

func Hash(plain string, config Config) (string, error) {
	if config.KeyLen == 0 {
		config.KeyLen = 32
	}
	if config.Cost == 0 {
		config.Cost = 32768
	}
	if config.Rounds == 0 {
		config.Rounds = 8
	}
	if config.Parallelism == 0 {
		config.Parallelism = 1
	}

	salt := make([]byte, 16)
	io.ReadFull(rand.Reader, salt)

	hash, err := scrypt.Key([]byte(plain), salt, config.Cost, config.Rounds, config.Parallelism, config.KeyLen)
	if err != nil {
		return "", err
	}

	hashString := format.Serialize(format.PHCConfig{
		ID:      "scrypt",
		Version: 0,
		Params: map[string]interface{}{
			"ln": config.Cost,
			"r":  config.Rounds,
			"p":  config.Parallelism,
		},
		Salt: hex.EncodeToString(salt[:]),
		Hash: hex.EncodeToString(hash[:]),
	})

	return hashString, nil
}

func Verify(hash string, plain string) (bool, error) {
	deserialize := format.Deserialize(hash)
	if !strings.HasPrefix(deserialize.ID, "scrypt") {
		return false, errors.New("hashed string is not scrypt instance")
	}

	var verifyHash []byte

	decodedHash, err := hex.DecodeString(deserialize.Hash)
	if err != nil {
		return false, err
	}
	keyLen := uint32(len(decodedHash))

	cost, err := strconv.ParseUint(deserialize.Params["ln"].(string), 10, 32)
	if err != nil {
		return false, err
	}
	rounds, err := strconv.ParseUint(deserialize.Params["r"].(string), 10, 32)
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

	verifyHash, err = scrypt.Key([]byte(plain), salt, int(cost), int(rounds), int(parallelism), int(keyLen))
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare(decodedHash, verifyHash) == 1 {
		return true, nil
	}
	return false, nil
}
