package pbkdf2

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/aldy505/phc-crypto/format"
	"golang.org/x/crypto/pbkdf2"
)

// Config initialize the config require to create a hash function
type Config struct {
	Rounds   int
	KeyLen   int
	HashFunc HashFunction
	SaltLen  int
}

const (
	// ROUNDS is the iteration counts.
	ROUNDS = 4096
	// KEYLEN is how many bytes to generate as output.
	KEY_LENGTH = 32
	// DEFAULT_HASHFUNCTION is for calculating HMAC. Defaulting to sha256.
	DEFAULT_HASHFUNCTION = SHA256
	// SALT_LENGTH is the default salth length in bytes.
	SALT_LENGTH = 16
)

type HashFunction int

const (
	SHA1 HashFunction = iota
	SHA256
	SHA224
	SHA512
	SHA384
	MD5
)

var ErrEmptyField error = errors.New("function parameters must not be empty")
var ErrInvalidHashFunction error = errors.New("invalid hash function was provided")

func hashFuncToName(h HashFunction) string {
	switch h {
	case SHA1:
		return "sha1"
	case SHA256:
		return "sha256"
	case SHA224:
		return "sha224"
	case SHA512:
		return "sha512"
	case SHA384:
		return "sha384"
	case MD5:
		return "md5"
	default:
		return ""
	}
}

// Hash creates a PHC-formatted hash with config provided
//
//      import (
//        "fmt"
//        "github.com/aldy505/phc-crypto/pbkdf2"
//      )
//
//      func main() {
//        hash, err := pbkdf2.Hash("password", pbkdf2.Config{
//          HashFunc: pbkdf2.SHA512,
//        })
//        if err != nil {
//          fmt.Println(err)
//        }
//        fmt.Println(hash) // $pbkdf2sha512$v=0$i=4096$87a39b3cf30626bc7cf6534ac3a14ddf$d32093416bf521ff0...
//      }
func Hash(plain string, config Config) (string, error) {
	if plain == "" {
		return "", ErrEmptyField
	}

	if config.Rounds == 0 {
		config.Rounds = ROUNDS
	}
	if config.KeyLen == 0 {
		config.KeyLen = KEY_LENGTH
	}
	if config.HashFunc < 0 || config.HashFunc > 5 {
		config.HashFunc = DEFAULT_HASHFUNCTION
	}
	if config.SaltLen == 0 {
		config.SaltLen = SALT_LENGTH
	}

	// minimum 64 bits, 128 bits is recommended
	salt := make([]byte, config.SaltLen)
	io.ReadFull(rand.Reader, salt)

	var hash []byte

	switch config.HashFunc {
	case SHA1:
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha1.New)
	case SHA256:
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha256.New)
	case SHA224:
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha256.New224)
	case SHA512:
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha512.New)
	case SHA384:
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, sha512.New384)
	case MD5:
		hash = pbkdf2.Key([]byte(plain), salt, config.Rounds, config.KeyLen, md5.New)
	}

	hashString := format.Serialize(format.PHCConfig{
		ID: "pbkdf2" + hashFuncToName(config.HashFunc),
		Params: map[string]interface{}{
			"i": config.Rounds,
		},
		Salt: hex.EncodeToString(salt[:]),
		Hash: hex.EncodeToString(hash[:]),
	})

	return hashString, nil
}

// Verify checks the hash if it's equal (by an algorithm) to plain text provided.
//
//      import (
//        "fmt"
//        "github.com/aldy505/phc-crypto/pbkdf2"
//      )
//
//      func main() {
//        hash := "$pbkdf2sha512$v=0$i=4096$87a39b3cf30626bc7cf6534ac3a14ddf$d32093416bf521ff0..."
//
//        verify, err := pbkdf2.Verify(hash, "password")
//        if err != nil {
//          fmt.Println(err)
//        }
//        fmt.Println(verify) // true
//      }
func Verify(hash string, plain string) (bool, error) {
	if hash == "" || plain == "" {
		return false, ErrEmptyField
	}

	deserialize := format.Deserialize(hash)

	if !strings.HasPrefix(deserialize.ID, "pbkdf2") {
		return false, errors.New("hashed string is not pbkdf2 instance")
	}

	decodedHash, err := hex.DecodeString(deserialize.Hash)
	if err != nil {
		return false, err
	}
	keyLen := int(len(decodedHash))

	rounds, err := strconv.ParseInt(deserialize.Params["i"].(string), 10, 32)
	if err != nil {
		return false, err
	}

	salt, err := hex.DecodeString(deserialize.Salt)
	if err != nil {
		return false, err
	}

	hashFunc := strings.Replace(deserialize.ID, "pbkdf2", "", 1)

	var verifyHash []byte

	switch hashFunc {
	case "sha1":
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha1.New)
	case "sha256":
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha256.New)
	case "sha224":
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha256.New224)
	case "sha512":
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha512.New)
	case "sha384":
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, sha512.New384)
	case "md5":
		verifyHash = pbkdf2.Key([]byte(plain), salt, int(rounds), keyLen, md5.New)
	default:
		return false, ErrInvalidHashFunction
	}

	if subtle.ConstantTimeCompare(decodedHash, verifyHash) == 1 {
		return true, nil
	}
	return false, nil
}
