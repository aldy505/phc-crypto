package format_test

import (
	"strings"
	"testing"

	"github.com/aldy505/phc-crypto/format"
)

func TestSerialize(t *testing.T) {
	serialized := format.Serialize(format.PHCConfig{
		ID:      "argon2id",
		Version: 2,
		Params: map[string]interface{}{
			"Something": "New",
			"Somewhere": "Far",
			"Meaning":   42,
		},
		Salt: "SaltyText",
		Hash: "HashyText",
	})

	destructured := strings.Split(serialized, "$")
	params := "Something=New,Somewhere=Far,Meaning=42"
	if destructured[1] != "argon2id" || destructured[2] != "v=2" || len(destructured[3]) != len(params) || destructured[4] != "SaltyText" || destructured[5] != "HashyText" {
		t.Error("Unexpected output: ", serialized)
	}
}

func TestDeserialize(t *testing.T) {
	deserialized := format.Deserialize("$argon2id$v=2$Something=New,Somewhere=Far,Meaning=42$SaltyText$HashyText")

	if deserialized.ID != "argon2id" {
		t.Error("Unexpected ID: ", deserialized.ID)
	}

	if deserialized.Version != 2 {
		t.Error("Unexpected Version: ", deserialized.Version)
	}

	if deserialized.Salt != "SaltyText" {
		t.Error("Unexpected Salt: ", deserialized.Salt)
	}

	if deserialized.Hash != "HashyText" {
		t.Error("Unexpected Hash: ", deserialized.Hash)
	}

	if deserialized.Params["Something"].(string) != "New" || deserialized.Params["Somewhere"].(string) != "Far" || deserialized.Params["Meaning"].(string) != "42" {
		t.Error("Unexpected Params: ", deserialized.Params)
	}
}
