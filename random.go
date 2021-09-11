package phccrypto

import (
	"crypto/rand"
	"math/big"
)

// Random returns a random algorithm for phcrypto.Use()
//
//      import (
//        "fmt"
//        "github.com/aldy505/phc-crypto"
//      )
//
//      func main() {
//        crypto, err := phccrypto.Use(phccrypto.Random(), phccrypto.Config{})
//        ...
//      }
func Random() Algorithm {
	random, _ := rand.Int(rand.Reader, big.NewInt(3))
	return Algorithm(random.Int64())
}