package opensecrets

import (
	"fmt"
	"os"
	"path/filepath"
)

type VaultService struct {
	MasterKeys MasterKeyManager
	Indexes    IndexStore
	Objects    ObjectStore
}

func NewVaultService(masterKeys MasterKeyManager, indexes IndexStore, objects ObjectStore) VaultService {
	return VaultService{
		MasterKeys: masterKeys,
		Indexes:    indexes,
		Objects:    objects,
	}
}

func (s VaultService) LockPaths(folderPath string, paths []string, keep bool) error {
	masterKey, err := s.MasterKeys.Load(folderPath)
	if err != nil {
		return err
	}

	index, err := s.Indexes.Load(folderPath, masterKey)
	if err != nil {
		return err
	}

	for _, path := range paths {
		relativePath, err := normalizeRelativePath(folderPath, path)
		if err != nil {
			return err
		}

		absolutePath := filepath.Join(folderPath, relativePath)
		info, err := os.Stat(absolutePath)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fmt.Errorf("lock paths: directories are not implemented yet: %s", relativePath)
		}

		plaintext, err := os.ReadFile(absolutePath)
		if err != nil {
			return err
		}

		objectID, err := s.Objects.Put(folderPath, masterKey, plaintext)
		if err != nil {
			return err
		}

		index.Entries[relativePath] = IndexEntry{
			ObjectID: objectID,
			Size:     info.Size(),
			Mode:     info.Mode(),
		}

		if !keep {
			err = os.Remove(absolutePath)
			if err != nil {
				return err
			}
		}
	}

	return s.Indexes.Save(folderPath, masterKey, index)
}

func (s VaultService) UnlockPaths(folderPath string, paths []string) error {
	masterKey, err := s.MasterKeys.Load(folderPath)
	if err != nil {
		return err
	}

	index, err := s.Indexes.Load(folderPath, masterKey)
	if err != nil {
		return err
	}

	for _, path := range paths {
		relativePath, err := normalizeRelativePath(folderPath, path)
		if err != nil {
			return err
		}

		entry, ok := index.Entries[relativePath]
		if !ok {
			return fmt.Errorf("unlock paths: path is not locked: %s", relativePath)
		}

		plaintext, err := s.Objects.Get(folderPath, masterKey, entry.ObjectID)
		if err != nil {
			return err
		}

		absolutePath := filepath.Join(folderPath, relativePath)
		err = os.MkdirAll(filepath.Dir(absolutePath), cDirPerm)
		if err != nil {
			return err
		}

		err = writeFileAtomically(absolutePath, plaintext, entry.Mode)
		if err != nil {
			return err
		}
	}

	return nil
}

func normalizeRelativePath(folderPath string, path string) (string, error) {
	if filepath.IsAbs(path) {
		relativePath, err := filepath.Rel(folderPath, path)
		if err != nil {
			return "", err
		}
		path = relativePath
	}

	cleanPath := filepath.Clean(path)
	if cleanPath == "." {
		return "", fmt.Errorf("path must not be the folder root")
	}
	if cleanPath == ".." || filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("path must stay within the folder")
	}
	if len(cleanPath) >= 3 && cleanPath[:3] == ".."+string(filepath.Separator) {
		return "", fmt.Errorf("path must stay within the folder")
	}

	return cleanPath, nil
}
