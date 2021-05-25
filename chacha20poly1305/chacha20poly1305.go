package chacha20poly1305

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/aldy505/phc-crypto/format"
	"golang.org/x/crypto/chacha20poly1305"
)

func Hash(plain string) (string, error) {
	salt := make([]byte, 32)
	io.ReadFull(rand.Reader, salt)

	aead, err := chacha20poly1305.NewX(salt)
	if err != nil {
		return "", err
	}

	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plain)+aead.Overhead())
	fmt.Println(nonce)
	// Encrypt the message and append the ciphertext to the nonce.
	hash := aead.Seal(nonce, nonce, []byte(plain), nil)

	hashString := format.Serialize(format.PHCConfig{
		Hash: hex.EncodeToString(hash),
		Salt: hex.EncodeToString(salt),
		Params: map[string]interface{}{
			"n": hex.EncodeToString(nonce),
		},
		Id: "chacha20poly1305",
	})
	return hashString, nil
}
