package format

import (
	"strconv"
	"strings"
)

// PHCConfig is a struct required for creating a PHC string
type PHCConfig struct {
	ID      string
	Version int
	Params  map[string]interface{}
	Salt    string
	Hash    string
}

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
	return "$" + config.ID + "$v=" + strconv.Itoa(config.Version) + "$" + strings.Join(params, ",") + "$" + config.Salt + "$" + config.Hash
}

// Deserialize converts a PHC string into a PHCConfig struct
func Deserialize(hash string) PHCConfig {
	hashArray := strings.Split(hash, "$")
	params := make(map[string]interface{})

	if len(hashArray[3]) != 0 {
		paramsArray := strings.Split(hashArray[3], ",")
		for _, value := range paramsArray {
			pair := strings.Split(value, "=")
			params[pair[0]] = pair[1]
		}
	}

	version, _ := strconv.Atoi(hashArray[2])
	return PHCConfig{
		ID:      hashArray[1],
		Version: version,
		Params:  params,
		Salt:    hashArray[4],
		Hash:    hashArray[5],
	}
}
