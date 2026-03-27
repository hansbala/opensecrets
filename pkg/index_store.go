package opensecrets

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	cStoreDir      = ".opensecrets"
	cStoreSubdir   = "store"
	cConfigFile    = "config.toml"
	cMasterKeyFile = "masterkey.enc"
	cIndexFile     = "index.enc"
	cIndexVersion  = 1
)

type Index struct {
	FormatVersion int
	Entries       map[string]IndexEntry
}

type IndexEntry struct {
	ObjectID string
	Size     int64
	Mode     os.FileMode
}

type IndexStore interface {
	Load(folderPath string, masterKey []byte) (*Index, error)
	Save(folderPath string, masterKey []byte, index *Index) error
}

type FilesystemIndexStore struct{}

func NewFilesystemIndexStore() IndexStore {
	return FilesystemIndexStore{}
}

func (s FilesystemIndexStore) Load(folderPath string, masterKey []byte) (*Index, error) {
	contents, err := os.ReadFile(indexPath(folderPath))
	if err != nil {
		if os.IsNotExist(err) {
			return &Index{
				FormatVersion: cIndexVersion,
				Entries:       map[string]IndexEntry{},
			}, nil
		}
		return nil, err
	}

	plaintext, err := decryptBytes(masterKey, contents)
	if err != nil {
		return nil, fmt.Errorf("decrypt index: %w", err)
	}

	var index Index
	err = json.Unmarshal(plaintext, &index)
	if err != nil {
		return nil, err
	}
	if index.Entries == nil {
		index.Entries = map[string]IndexEntry{}
	}

	return &index, nil
}

func (s FilesystemIndexStore) Save(folderPath string, masterKey []byte, index *Index) error {
	if index.FormatVersion == 0 {
		index.FormatVersion = cIndexVersion
	}
	if index.Entries == nil {
		index.Entries = map[string]IndexEntry{}
	}

	plaintext, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}

	ciphertext, err := encryptBytes(masterKey, plaintext)
	if err != nil {
		return err
	}

	err = os.MkdirAll(storeRootPath(folderPath), cDirPerm)
	if err != nil {
		return err
	}

	return writeFileAtomically(indexPath(folderPath), ciphertext, cFilePerm)
}

func indexPath(folderPath string) string {
	return filepath.Join(storeRootPath(folderPath), cIndexFile)
}

func storeRootPath(folderPath string) string {
	return filepath.Join(folderPath, cStoreDir)
}

func storeObjectsPath(folderPath string) string {
	return filepath.Join(storeRootPath(folderPath), cStoreSubdir)
}

func configPath(folderPath string) string {
	return filepath.Join(storeRootPath(folderPath), cConfigFile)
}

func masterKeyPath(folderPath string) string {
	return filepath.Join(storeRootPath(folderPath), cMasterKeyFile)
}
