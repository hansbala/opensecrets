package opensecrets

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

func encryptBytes(masterKey []byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, err
	}

	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func decryptBytes(masterKey []byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < chacha20poly1305.NonceSizeX {
		return nil, errors.New("ciphertext is too short")
	}

	nonce := ciphertext[:chacha20poly1305.NonceSizeX]
	body := ciphertext[chacha20poly1305.NonceSizeX:]

	return aead.Open(nil, nonce, body, nil)
}

func randomBytes(length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
