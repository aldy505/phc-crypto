# PHC Crypto - Bcrypt

[![Go Reference](https://pkg.go.dev/badge/github.com/aldy505/phc-crypto.svg)](https://pkg.go.dev/github.com/aldy505/phc-crypto/bcrypt)

According to [Wikipedia](https://en.wikipedia.org/wiki/Bcrypt):

bcrypt is a password-hashing function designed by Niels Provos and David Mazières, based on the Blowfish cipher and
presented at USENIX in 1999. Besides incorporating a salt to protect against rainbow table attacks, bcrypt is an
adaptive function: over time, the iteration count can be increased to make it slower, so it remains resistant to
brute-force search attacks even with increasing computation power.

## Configuration options

| Key    | Type  | Default | Notes                                        |
|--------|-------|---------|----------------------------------------------|
| Rounds | `int` | 10      | Cost of rounds, minimum of 4, maximum of 31. |

## Usage with PHC Crypto

```go
package main

import (
	"fmt"
	"github.com/aldy505/phc-crypto"
)

func main() {
	crypto, err := phccrypto.Use(phccrypto.Bcrypt, phccrypto.Config{
		Rounds: 20,
	})
	if err != nil {
		fmt.Println(err)
	}

	hash, err := phccrypto.Hash("password")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hash) // $bcrypt$v=0$r=12$$2432612431322479356256373563666e503557...

	verify, err := phccrypto.Verify(hash, "password")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(verify) // true
}
```

## Standalone usage

```go
package main

import (
	"fmt"
	"github.com/aldy505/phc-crypto/bcrypt"
)

func main() {
	hash, err := bcrypt.Hash("password", bcrypt.Config{
		Rounds: 12,
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hash) // $bcrypt$v=0$r=12$$2432612431322479356256373563666e503557...

	verify, err := bcrypt.Verify(hash, "password")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(verify) // true
}
```