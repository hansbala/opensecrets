package opensecrets

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

type ObjectStore interface {
	Put(folderPath string, masterKey []byte, plaintext []byte) (string, error)
	Get(folderPath string, masterKey []byte, objectID string) ([]byte, error)
	Delete(folderPath string, objectID string) error
}

type FilesystemObjectStore struct{}

func NewFilesystemObjectStore() ObjectStore {
	return FilesystemObjectStore{}
}

func (s FilesystemObjectStore) Put(folderPath string, masterKey []byte, plaintext []byte) (string, error) {
	objectID := objectIDForPlaintext(plaintext)
	objectPath := objectPath(folderPath, objectID)

	err := os.MkdirAll(filepath.Dir(objectPath), cDirPerm)
	if err != nil {
		return "", err
	}

	ciphertext, err := encryptBytes(masterKey, plaintext)
	if err != nil {
		return "", err
	}

	err = writeFileAtomically(objectPath, ciphertext, cFilePerm)
	if err != nil {
		return "", err
	}

	return objectID, nil
}

func (s FilesystemObjectStore) Get(folderPath string, masterKey []byte, objectID string) ([]byte, error) {
	ciphertext, err := os.ReadFile(objectPath(folderPath, objectID))
	if err != nil {
		return nil, err
	}

	return decryptBytes(masterKey, ciphertext)
}

func (s FilesystemObjectStore) Delete(folderPath string, objectID string) error {
	err := os.Remove(objectPath(folderPath, objectID))
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

func objectPath(folderPath string, objectID string) string {
	prefix := objectID
	if len(objectID) >= 2 {
		prefix = objectID[:2]
	}

	return filepath.Join(storeObjectsPath(folderPath), prefix, objectID)
}

func objectIDForPlaintext(plaintext []byte) string {
	digest := sha256.Sum256(plaintext)
	return hex.EncodeToString(digest[:])
}
