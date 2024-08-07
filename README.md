# PHC Crypto

[![GitHub release (latest SemVer including pre-releases)](https://img.shields.io/github/v/release/aldy505/phc-crypto?include_prereleases)](https://github.com/aldy505/phc-crypto/releases) [![Go Reference](https://pkg.go.dev/badge/github.com/aldy505/phc-crypto.svg)](https://pkg.go.dev/github.com/aldy505/phc-crypto) [![Go Report Card](https://goreportcard.com/badge/github.com/aldy505/phc-crypto)](https://goreportcard.com/report/github.com/aldy505/phc-crypto) [![GitHub](https://img.shields.io/github/license/aldy505/phc-crypto)](https://github.com/aldy505/phc-crypto/blob/master/LICENSE) [![codecov](https://codecov.io/gh/aldy505/phc-crypto/branch/master/graph/badge.svg?token=HUTQURBZ73)](https://codecov.io/gh/aldy505/phc-crypto) [![CodeFactor](https://www.codefactor.io/repository/github/aldy505/phc-crypto/badge)](https://www.codefactor.io/repository/github/aldy505/phc-crypto) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/16c40f49aabe4e89afea7c1e1d90a483)](https://www.codacy.com/gh/aldy505/phc-crypto/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=aldy505/phc-crypto&amp;utm_campaign=Badge_Grade) [![Build test](https://github.com/aldy505/phc-crypto/actions/workflows/build.yml/badge.svg)](https://github.com/aldy505/phc-crypto/actions/workflows/build.yml) [![Build test](https://github.com/aldy505/phc-crypto/actions/workflows/coverage.yml/badge.svg)](https://github.com/aldy505/phc-crypto/actions/workflows/coverage.yml)

Inspired by [Upash](https://github.com/simonepri/upash), also
implementing [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md)

## Usage

Currently there are two options of using this package:

1. Import all
2. Import specific hash function

Bear in mind, these usage function might be changed in the near future.

### Currently supported formats

* Bcrypt
* Argon2i & Argon2id
* PBKDF2
* Scrypt

For details regarding configs, please refer to their own directory.

### Option 1 - Import all

```go
package main

import (
	"fmt"
	"github.com/aldy505/phc-crypto"
)

func main() {
	// Create a crypto instance
	// Change the scope name to your prefered hashing algorithm
	// Available options are: Bcrypt, Scrypt, Argon2, PBKDF2
	crypto, err := phccrypto.Use(phccrypto.Scrypt, phccrypto.Config{})

	hash, err := crypto.Hash("password123")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hash) // returns string ($scrypt$v=0$p=1,ln=32768,r=8$402ffb0b23cd3d3a$62daeae2ac...)

	verify, err := crypto.Verify(hash, "password123")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(verify) // returns boolean (true/false)
}
```

### Option 2 - Import specific hash function

```go
package main

import "github.com/aldy505/phc-crypto/scrypt"

func main() {
	// Change the scope name to your prefered hashing algorithm
	hash, err := scrypt.Hash("password123", scrypt.Config{})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hash) // returns string ($scrypt$v=0$p=1,ln=32768,r=8$402ffb0b23cd3d3a$62daeae2ac...)

	verify, err := scrypt.Verify(hash, "password123")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(verify) // returns boolean (true/false)
}
```

## Contribute

Yes please! I'm still new to Go and I create this module (or package if you will) to help me fulfill a need on my
project. Feel free to refactor, add new feature, fix unknown bugs, and have fun!

## LICENSE

```
MIT License

Copyright (c) 2024 Reinaldy Rafli and PHC Crypto collaborators

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```