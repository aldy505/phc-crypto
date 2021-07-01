# PHC Crypto - Argon2

[![Go Reference](https://pkg.go.dev/badge/github.com/aldy505/phc-crypto.svg)](https://pkg.go.dev/github.com/aldy505/phc-crypto/argon2)

According to [Wikipedia](https://en.wikipedia.org/wiki/Argon2):

Argon2 is a key derivation function that was selected as the winner of the Password Hashing Competition in July 2015. It was designed by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich from the University of Luxembourg. The reference implementation of Argon2 is released under a Creative Commons CC0 license (i.e. public domain) or the Apache License 2.0, and provides three related versions:

  * Argon2d maximizes resistance to GPU cracking attacks. It accesses the memory array in a password dependent order, which reduces the possibility of time–memory trade-off (TMTO) attacks, but introduces possible side-channel attacks.
  * Argon2i is optimized to resist side-channel attacks. It accesses the memory array in a password independent order.
  * Argon2id is a hybrid version. It follows the Argon2i approach for the first half pass over memory and the Argon2d approach for subsequent passes. The Internet draft recommends using Argon2id except when there are reasons to prefer one of the other two modes.

All three modes allow specification by three parameters that control:

  * execution time
  * memory required
  * degree of parallelism

## Configuration options

| Key | Type | Default | Notes
|---|---|---|---|
| Time | `int` | 32768 | Number of iterations to perform |
| Memory | `int` | 8 | Amount of memory (in kilobytes) to use |
| Parallelism | `int` | 4 | Parallelism factor (threads to run in parallel). |
| Variant | `Variant` | `argon2.ID` | Argon2 variant to be used (`argon2.ID` or `argon2.I`)|
| KeyLen | `int` | 64 | How many bytes to generate as output. | 
| SaltLen | `int` | 16 | Salt length in bytes |

## Usage with PHC Crypto

```bash
$ go get github.com/aldy505/phc-crypto
```

```go
import (
  "fmt"
  "github.com/aldy505/phc-crypto"
)

func main() {
  crypto, err := phccrypto.Use(phccrypto.Argon2, phccrypto.Config{
    Parallelism: 3,
  })
  if err != nil {
    fmt.Println(err)
  }

  hash, err := phccrypto.Hash("password")
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(hash) // $argon2id$v=19$m=65536,t=16,p=3$8400b4e5f01f30092b794de34c61a6fdfea6b6b446560fda08a876bd11e9c62e$3fd77927d189...

  verify, err := phccrypto.Verify(hash, "password")
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(verify) // true
}
```

## Standalone usage

```bash
$ go get github.com/aldy505/phc-crypto/argon2
```

```go
import (
  "fmt"
  "github.com/aldy505/phc-crypto/argon2"
)

func main() {

  hash, err := argon2.Hash("password", argon2.Config{
    Parallelism: 3,
    Variant: argon2.I,
  })
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(hash) // $argon2i$v=19$m=65536,t=16,p=3$8400b4e5f01f30092b794de34c61a6fdfea6b6b446560fda08a876bd11e9c62e$3fd77927d189...

  verify, err := argon2.Verify(hash, "password")
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(verify) // true
}
```