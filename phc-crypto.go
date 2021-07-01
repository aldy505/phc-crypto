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
	Variant     argon2.Variant
	HashFunc    string
}

// Use initiates the hash/verify function.
// Available hash functions are: bcrypt, scrypt, argon2, pbkdf2.
// Please refer to each hash folder for configuration information.
func Use(name Algorithm, config Config) (*Algo, error) {
	algo := &Algo{
		Name:   name,
		Config: &config,
	}
	return algo, nil
}

// Hash returns a PHC formatted string of a hash function (that was initiated from Use).
func (a *Algo) Hash(plain string) (hash string, err error) {
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
		err = errors.New("the algorithm provided is not supported")
		return
	}
}

// Verify returns a boolean of a hash function (that was initiated from Use).
func (a *Algo) Verify(hash, plain string) (verify bool, err error) {
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
		err = errors.New("the algorithm provided is not (yet) supported")
		return
	}
}
