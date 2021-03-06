package phccrypto

import (
	"errors"

	"github.com/aldy505/phc-crypto/argon2"
	"github.com/aldy505/phc-crypto/bcrypt"
	"github.com/aldy505/phc-crypto/pbkdf2"
	"github.com/aldy505/phc-crypto/scrypt"
)

type Algorithm int

const (
	Scrypt Algorithm = iota
	Bcrypt
	Argon2
	PBKDF2
)

// Algo returns struct that will be use on Hash and Verify function
type Algo struct {
	Name   Algorithm
	Config *Config
}

// Config returns the general config of the hashing function
type Config struct {
	Cost        int
	Rounds      int
	Parallelism int
	KeyLen      int
	SaltLen     int
	Variant     argon2.Variant
	HashFunc    pbkdf2.HashFunction
}

var ErrAlgoNotSupported error = errors.New("the algorithm provided is not supported")
var ErrEmptyField error = errors.New("function parameters must not be empty")

// Use initiates the hash/verify function.
// Available hash functions are: bcrypt, scrypt, argon2, pbkdf2.
// Please refer to each hash folder for configuration information.
//
//      import (
//      	"fmt"
//      	"github.com/aldy505/phc-crypto"
//      )
//
//      func main() {
//      	// Create a crypto instance
//      	// Change the scope name to your prefered hashing algorithm
//      	// Available options are: Bcrypt, Scrypt, Argon2, PBKDF2
//      	crypto, err := phccrypto.Use(phccrypto.Scrypt, phccrypto.Config{})
//
//        hash, err := crypto.Hash("password123")
//        if err != nil {
//        	fmt.Println(err)
//        }
//        fmt.Println(hash) // returns string ($scrypt$v=0$p=1,ln=32768,r=8$402ffb0b23cd3d3a$62daeae2ac...)
//
//      	verify, err := crypto.Verify(hash, "password123")
//      	if err != nil {
//      		fmt.Println(err)
//      	}
//      	fmt.Println(verify) // returns boolean (true/false)
//      }
func Use(name Algorithm, config Config) (*Algo, error) {
	algo := &Algo{
		Name:   name,
		Config: &config,
	}
	return algo, nil
}

// Hash returns a PHC formatted string of a hash function (that was initiated from Use).
func (a *Algo) Hash(plain string) (hash string, err error) {
	if plain == "" {
		hash = ""
		err = ErrEmptyField
		return
	}

	switch a.Name {
	case Scrypt:
		hash, err = scrypt.Hash(plain, scrypt.Config{
			Cost:        a.Config.Cost,
			Rounds:      a.Config.Rounds,
			Parallelism: a.Config.Parallelism,
			KeyLen:      a.Config.KeyLen,
		})
		return
	case Bcrypt:
		hash, err = bcrypt.Hash(plain, bcrypt.Config{
			Rounds: a.Config.Rounds,
		})
		return
	case Argon2:
		hash, err = argon2.Hash(plain, argon2.Config{
			Time:        a.Config.Rounds,
			Memory:      a.Config.Cost,
			Parallelism: a.Config.Parallelism,
			KeyLen:      a.Config.KeyLen,
			Variant:     a.Config.Variant,
		})
		return
	case PBKDF2:
		hash, err = pbkdf2.Hash(plain, pbkdf2.Config{
			Rounds:   a.Config.Rounds,
			KeyLen:   a.Config.KeyLen,
			HashFunc: a.Config.HashFunc,
		})
		return
	default:
		hash = ""
		err = ErrAlgoNotSupported
		return
	}
}

// Verify returns a boolean of a hash function (that was initiated from Use).
func (a *Algo) Verify(hash, plain string) (verify bool, err error) {
	if hash == "" || plain == "" {
		verify = false
		err = ErrEmptyField
		return
	}

	switch a.Name {
	case Scrypt:
		verify, err = scrypt.Verify(hash, plain)
		return
	case Bcrypt:
		verify, err = bcrypt.Verify(hash, plain)
		return
	case Argon2:
		verify, err = argon2.Verify(hash, plain)
		return
	case PBKDF2:
		verify, err = pbkdf2.Verify(hash, plain)
		return
	default:
		verify = false
		err = ErrAlgoNotSupported
		return
	}
}
