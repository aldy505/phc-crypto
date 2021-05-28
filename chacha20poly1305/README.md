# PHC Crypto - Scrypt

[![Go Reference](https://pkg.go.dev/badge/github.com/aldy505/phc-crypto.svg)](https://pkg.go.dev/github.com/aldy505/phc-crypto/chacha20poly1305)

According to [Wikipedia](https://en.wikipedia.org/wiki/Poly1305)

Poly1305 is a cryptographic message authentication code (MAC) created by Daniel J. Bernstein. It can be used to verify the data integrity and the authenticity of a message. A variant of Bernstein's Poly1305 that does not require AES has been standardized by the Internet Engineering Task Force in RFC 8439. 

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
  crypto, err := phccrypto.Use("chacha20poly1305", phccrypto.Config{})
  if err != nil {
    fmt.Println(err)
  }

  hash, err := phccrypto.Hash("password")
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(hash) // 

  verify, err := phccrypto.Verify(hash, "password")
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(verify) // true
}
```

## Standalone usage

```bash
$ go get github.com/aldy505/phc-crypto/chacha20poly1305
```

```go
import (
  "fmt"
  "github.com/aldy505/phc-crypto/chacha20poly1305"
)

func main() {

  hash, err := chacha20poly1305.Hash("password")
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(hash) // $chacha20poly1305$v=0$$9c20e454661522991120962c7a36951ea15b9a0a015...

  verify, err := chacha20poly1305.Verify(hash, "password")
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(verify) // true
}
```

You can also use it to encrypt/decrypt some text, but you should add another package

```bash
$ go get github.com/aldy505/phc-crypto/format
```

```go
import (
  "fmt"
  "hex"

  "github.com/aldy505/phc-crypto/format"
  "github.com/aldy505/phc-crypto/chacha20poly1305"
)

func main() {
  text := "This is a very secret text"

  hash, err := chacha20poly1305.Hash(text)
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(hash) // $chacha20poly1305$v=0$$9c20e454661522991120962c7a36951ea15b9a0a015...

  deserialize := format.Deserialize(hash)

  decodedSalt, err := hex.DecodeString(deserialize.Salt)
	if err != nil {
		fmt.Println(err)
	}

	decodedHash, err := hex.DecodeString(deserialize.Hash)
	if err != nil {
		fmt.Println(err)
	}

  decrypted, err := chacha20poly1305.Decrypt(decodedSalt, decodedHash)
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(decrypted) // This is a very secret text
}
```