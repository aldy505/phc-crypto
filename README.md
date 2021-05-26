# PHC Crypto

[![GitHub release (latest SemVer including pre-releases)](https://img.shields.io/github/v/release/aldy505/phc-crypto?include_prereleases)](https://github.com/aldy505/phc-crypto/releases) [![GitHub](https://img.shields.io/github/license/aldy505/phc-crypto)](https://github.com/aldy505/phc-crypto/blob/master/LICENSE) [![Codecov](https://img.shields.io/codecov/c/gh/aldy505/phc-crypto)](https://www.codecov.io/gh/aldy505/phc-crypto) [![CodeFactor](https://www.codefactor.io/repository/github/aldy505/phc-crypto/badge)](https://www.codefactor.io/repository/github/aldy505/phc-crypto) [![Build test](https://github.com/aldy505/phc-crypto/actions/workflows/build.yml/badge.svg)](https://github.com/aldy505/phc-crypto/actions/workflows/build.yml) [![Build test](https://github.com/aldy505/phc-crypto/actions/workflows/coverage.yml/badge.svg)](https://github.com/aldy505/phc-crypto/actions/workflows/coverage.yml)

A work in progress.

Inspired by [Upash](https://github.com/simonepri/upash), also implementing [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md)

## Usage

Bear in mind, these usage function might changed in the near future.

### Currently working formats:

* Bcrypt
* PBKDF2
* Scrypt

```bash
$ go get github.com/aldy505/phc-crypto/bcrypt
$ go get github.com/aldy505/phc-crypto/pbkdf2
$ go get github.com/aldy505/phc-crypto/scrypt
```

```go
import "github.com/aldy505/phc-crypto/scrypt"

func main() {
  // Change the scope name to your prefered hashing algorithm
  hash, err := scrypt.Hash("password123", scrypt.Config{})
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(hash) // returns string ($scrypt$v=0$p=1,ln=32768,r=8$402ffb0b23cd3d3a60bf7a86f6ac4db5$62daeae2ac...)

  verify, err := scrypt.Verify(hash, "password123")
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(verify) // returns boolean (true/false)
}

```

### Currently work-in-progress formats:

* Argon2 (argon2i & argon2id)
* Chacha20poly1305

## Want to contribute?

Yes please! I'm still new to Go and I create this module (or package if you will) to help me fulfill a need on my project. Feel free to refactor, add new feature, fix unknown bugs, and have fun!

## LICENSE

MIT License

Copyright (c) 2021-present Reinaldy Rafli and PHC Crypto collaborators

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