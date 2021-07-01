# PHC Crypto - Scrypt

[![Go Reference](https://pkg.go.dev/badge/github.com/aldy505/phc-crypto.svg)](https://pkg.go.dev/github.com/aldy505/phc-crypto/pbkdf2)

According to [Wikipedia](https://en.wikipedia.org/wiki/PBKDF2):

In cryptography, PBKDF1 and PBKDF2 (Password-Based Key Derivation Function 1 and 2) are key derivation functions with a sliding computational cost, used to reduce vulnerabilities of brute-force attacks. PBKDF2 is part of RSA Laboratories' Public-Key Cryptography Standards (PKCS) series, specifically PKCS #5 v2.0, also published as Internet Engineering Task Force's RFC 2898. It supersedes PBKDF1, which could only produce derived keys up to 160 bits long. RFC 8018 (PKCS #5 v2.1), published in 2017, recommends PBKDF2 for password hashing.

## Configuration options

| Key | Type | Default | Notes
|---|---|---|---|
| Rounds | `int` | 4096 | Iteration counts. |
| HashFunc | `string` | `sha256` | For calculating HMAC |
| KeyLen | `int` | 32 | How many bytes to generate as output. |
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
  crypto, err := phccrypto.Use(phccrypto.PBKDF2, phccrypto.Config{
    HashFunc: "sha512",
  })
  if err != nil {
    fmt.Println(err)
  }

  hash, err := phccrypto.Hash("password")
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(hash) // $pbkdf2sha512$v=0$i=4096$87a39b3cf30626bc7cf6534ac3a14ddf$d32093416bf521ff0...

  verify, err := phccrypto.Verify(hash, "password")
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(verify) // true
}
```

## Standalone usage

```bash
$ go get github.com/aldy505/phc-crypto/pbkdf2
```

```go
import (
  "fmt"
  "github.com/aldy505/phc-crypto/pbkdf2"
)

func main() {

  hash, err := pbkdf2.Hash("password", pbkdf2.Config{
    HashFunc: "sha512",
  })
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(hash) // $pbkdf2sha512$v=0$i=4096$87a39b3cf30626bc7cf6534ac3a14ddf$d32093416bf521ff0...

  verify, err := pbkdf2.Verify(hash, "password")
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(verify) // true
}
```