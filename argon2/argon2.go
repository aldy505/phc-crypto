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

type Config struct {
	Time        uint32
	Memory      uint32
	Parallelism uint8
	KeyLen      uint32
	Variant     string
}

func Hash(plain string, config Config) (string, error) {
	if config.KeyLen == 0 {
		config.KeyLen = 64
	}
	if config.Time == 0 {
		config.Time = 1
	}
	if config.Memory == 0 {
		config.Memory = 64 * 1024
	}
	if config.Parallelism == 0 {
		config.Parallelism = 4
	}
	if config.Variant == "" {
		config.Variant = "id"
	}
	salt := make([]byte, 32)
	io.ReadFull(rand.Reader, salt)

	var hash []byte
	if config.Variant == "id" {
		hash = argon2.IDKey([]byte(plain), salt, config.Time, config.Memory, config.Parallelism, config.KeyLen)
	} else if config.Variant == "i" {
		hash = argon2.Key([]byte(plain), salt, config.Time, config.Memory, config.Parallelism, config.KeyLen)
	}
	version := argon2.Version
	hashString := format.Serialize(format.PHCConfig{
		Id:      "argon2" + config.Variant,
		Version: version,
		Params: map[string]interface{}{
			"m": strconv.Itoa(int(config.Memory)),
			"t": strconv.Itoa(int(config.Time)),
			"p": string(config.Parallelism),
		},
		Salt: hex.EncodeToString(salt),
		Hash: hex.EncodeToString(hash),
	})
	return hashString, nil
}

func Verify(hash string, plain string) (bool, error) {
	deserialize := format.Deserialize(hash)
	if strings.HasPrefix(deserialize.Id, "argon2") == false {
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

	if deserialize.Id == "argon2id" {
		verifyHash = argon2.IDKey([]byte(plain), []byte(deserialize.Salt), uint32(time), uint32(memory), uint8(parallelism), keyLen)
	} else if deserialize.Id == "argon2i" {
		verifyHash = argon2.Key([]byte(plain), []byte(deserialize.Salt), uint32(time), uint32(memory), uint8(parallelism), keyLen)
	}

	if subtle.ConstantTimeCompare(verifyHash, decodedHash) == 1 {
		return true, nil
	}
	return false, nil
}
