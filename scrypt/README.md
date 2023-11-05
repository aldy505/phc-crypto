# PHC Crypto - Scrypt

[![Go Reference](https://pkg.go.dev/badge/github.com/aldy505/phc-crypto.svg)](https://pkg.go.dev/github.com/aldy505/phc-crypto/scrypt)

According to [Wikipedia](https://en.wikipedia.org/wiki/Scrypt):

scrypt (pronounced "ess crypt") is a password-based key derivation function created by Colin Percival, originally for
the Tarsnap online backup service. The algorithm was specifically designed to make it costly to perform large-scale
custom hardware attacks by requiring large amounts of memory. In 2016, the scrypt algorithm was published by IETF as RFC
7914. A simplified version of scrypt is used as a proof-of-work scheme by a number of cryptocurrencies, first
implemented by an anonymous programmer called ArtForz in Tenebrix and followed by Fairbrix and Litecoin soon after.

## Configuration options

| Key         | Type  | Default | Notes                                                                            |
|-------------|-------|---------|----------------------------------------------------------------------------------|
| Cost        | `int` | 32768   | Iterations count (affects memory and CPU usage)                                  |
| Rounds      | `int` | 8       | Block size (affects memory and CPU usage)                                        |
| Parallelism | `int` | 1       | Parallelism factor (threads to run in parallel - affects the memory, CPU usage). |
| KeyLen      | `int` | 32      | How many bytes to generate as output.                                            |
| SaltLen     | `int` | 16      | Salt length in bytes                                                             |

## Usage with PHC Crypto

```go
package main

import (
	"fmt"
	"github.com/aldy505/phc-crypto"
)

func main() {
	crypto, err := phccrypto.Use(phccrypto.Scrypt, phccrypto.Config{
		Parallelism: 3,
	})
	if err != nil {
		fmt.Println(err)
	}

	hash, err := phccrypto.Hash("password")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hash) // $scrypt$v=0$p=3,ln=32768,r=8$64ecb15ec1aa81bc403a892efb2289ce$4fc8d3bc...

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
	"github.com/aldy505/phc-crypto/scrypt"
)

func main() {
	hash, err := scrypt.Hash("password", scrypt.Config{
		Parallelism: 3,
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hash) // $scrypt$v=0$p=3,ln=32768,r=8$64ecb15ec1aa81bc403a892efb2289ce$4fc8d3bc...

	verify, err := scrypt.Verify(hash, "password")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(verify) // true
}
```