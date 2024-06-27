// Package format is meant to be utils for PHC Crypto package.
// The point is to be able to serialize and deserialize strings or interface in and out of PHC string format.
package format

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// PHCConfig is a struct required for creating a PHC string
type PHCConfig struct {
	ID      string
	Version int
	Params  map[string]interface{}
	Salt    []byte
	Hash    []byte
}

var ErrInvalidFormat = errors.New("invalid format")

// Serialize converts PHCConfig struct into a PHC string.
// See https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
func Serialize(config PHCConfig) string {
	var params []string
	for key, value := range config.Params {
		switch v := value.(type) {
		case string:
			params = append(params, key+"="+v)
		case int:
			params = append(params, key+"="+strconv.Itoa(v))
		}

	}
	return "$" + config.ID + "$v=" + strconv.Itoa(config.Version) + "$" + strings.Join(params, ",") + "$" + base64.RawStdEncoding.EncodeToString(config.Salt) + "$" + base64.RawStdEncoding.EncodeToString(config.Hash)
}

// Deserialize converts a PHC string into a PHCConfig struct
func Deserialize(hash string) (PHCConfig, error) {
	hashArray := strings.Split(hash, "$")
	params := make(map[string]interface{})

	if len(hashArray[3]) != 0 {
		paramsArray := strings.Split(hashArray[3], ",")
		for _, value := range paramsArray {
			pair := strings.Split(value, "=")
			params[pair[0]] = pair[1]
		}
	}

	version, _ := strconv.Atoi(strings.Replace(hashArray[2], "v=", "", 1))

	salt, err := base64.RawStdEncoding.DecodeString(hashArray[4])
	if err != nil {
		return PHCConfig{}, fmt.Errorf("%w: %v", ErrInvalidFormat, err)
	}

	h, err := base64.RawStdEncoding.DecodeString(hashArray[5])
	if err != nil {
		return PHCConfig{}, fmt.Errorf("%w: %v", ErrInvalidFormat, err)
	}

	return PHCConfig{
		ID:      hashArray[1],
		Version: version,
		Params:  params,
		Salt:    salt,
		Hash:    h,
	}, nil
}
