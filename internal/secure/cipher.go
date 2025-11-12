package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// Cipher encrypts and decrypts small pieces of data using AES-GCM.
type Cipher struct {
	key []byte
}

// NewCipher constructs a cipher from a 32-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("cipher key must be 32 bytes, got %d", len(key))
	}
	copied := make([]byte, len(key))
	copy(copied, key)
	return &Cipher{key: copied}, nil
}

// Encrypt encodes plaintext into a base64 string.
func (c *Cipher) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt decodes a base64 encoded ciphertext.
func (c *Cipher) Decrypt(ciphertext string) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := data[:gcm.NonceSize()]
	payload := data[gcm.NonceSize():]

	plain, err := gcm.Open(nil, nonce, payload, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}
