package format

import (
	"strconv"
	"strings"
)

type PHCConfig struct {
	Id      string
	Version int
	Params  map[string]interface{}
	Salt    string
	Hash    string
}

func Serialize(config PHCConfig) string {
	var params []string
	for key, value := range config.Params {
		params = append(params, key+"="+strconv.Itoa(value.(int)))
	}
	return "$" + config.Id + "$v=" + strconv.Itoa(config.Version) + "$" + strings.Join(params, ",") + "$" + config.Salt + "$" + config.Hash
}

func Deserialize(hash string) PHCConfig {
	hashArray := strings.Split(hash, "$")
	params := make(map[string]interface{})

	paramsArray := strings.Split(hashArray[3], ",")
	for _, value := range paramsArray {
		pair := strings.Split(value, "=")
		params[pair[0]] = pair[1]
	}
	version, _ := strconv.Atoi(hashArray[2])
	return PHCConfig{
		Id:      hashArray[1],
		Version: version,
		Params:  params,
		Salt:    hashArray[4],
		Hash:    hashArray[5],
	}
}
