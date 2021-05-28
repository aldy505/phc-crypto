package chacha20poly1305

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strings"

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
	io.ReadFull(rand.Reader, nonce)
	// Encrypt the message and append the ciphertext to the nonce.
	hash := aead.Seal(nonce, nonce, []byte(plain), nil)

	hashString := format.Serialize(format.PHCConfig{
		Hash: hex.EncodeToString(hash),
		Salt: hex.EncodeToString(salt),
		ID:   "chacha20poly1305",
	})
	return hashString, nil
}

func Decrypt(salt []byte, hash []byte) (string, error) {
	aead, err := chacha20poly1305.NewX(salt)
	if err != nil {
		return "", err
	}

	nonce, cipherText := hash[:aead.NonceSize()], hash[aead.NonceSize():]

	decrypted, err := aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func Verify(hash string, plain string) (bool, error) {
	deserialize := format.Deserialize(hash)
	if !strings.HasPrefix(deserialize.ID, "chacha20poly1305") {
		return false, errors.New("hashed string is not a chacha20poly1305 instance")
	}

	salt, err := hex.DecodeString(deserialize.Salt)
	if err != nil {
		return false, err
	}

	decodedHash, err := hex.DecodeString(deserialize.Hash)
	if err != nil {
		return false, err
	}

	decrypted, err := Decrypt(salt, decodedHash)
	if err != nil {
		return false, err
	}

	if decrypted == plain {
		return true, nil
	}
	return false, nil
}
