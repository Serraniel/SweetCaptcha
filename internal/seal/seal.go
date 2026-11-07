// Package seal encrypts and authenticates opaque values handed to clients.
//
// Challenges and pass tokens are sealed rather than merely signed so that
// clients cannot read scores or reason codes and use them as a detection oracle.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// ErrInvalid is returned for any value that fails to decode or authenticate.
var ErrInvalid = errors.New("invalid sealed value")

// Box seals JSON-encodable values with AES-256-GCM.
type Box struct{ aead cipher.AEAD }

// New returns a Box for a 32-byte key.
func New(key []byte) (*Box, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts v and returns a URL-safe string.
func (b *Box) Seal(v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b.aead.Seal(nonce, nonce, plain, nil)), nil
}

// Open authenticates and decrypts s into v.
func (b *Box) Open(s string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) < b.aead.NonceSize() {
		return ErrInvalid
	}
	plain, err := b.aead.Open(nil, raw[:b.aead.NonceSize()], raw[b.aead.NonceSize():], nil)
	if err != nil {
		return ErrInvalid
	}
	if json.Unmarshal(plain, v) != nil {
		return ErrInvalid
	}
	return nil
}
