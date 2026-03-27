package opensecrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

func (s VaultService) LockPaths(folderPath string, paths []string, keep bool, force bool) error {
	masterKey, err := s.MasterKeys.Load(folderPath)
	if err != nil {
		return err
	}

	index, err := s.Indexes.Load(folderPath, masterKey)
	if err != nil {
		return err
	}

	lockablePaths, err := expandLockPaths(folderPath, paths)
	if err != nil {
		return err
	}

	for _, relativePath := range lockablePaths {
		absolutePath := filepath.Join(folderPath, relativePath)
		info, err := os.Stat(absolutePath)
		if err != nil {
			return err
		}
		if _, ok := index.Entries[relativePath]; ok && !force {
			return fmt.Errorf("%s is already locked. Pass --force to overwrite.", relativePath)
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

			err = pruneEmptyParentDirs(folderPath, relativePath)
			if err != nil {
				return err
			}
		}
	}

	return s.Indexes.Save(folderPath, masterKey, index)
}

func (s VaultService) UnlockPaths(folderPath string, paths []string, force bool) error {
	masterKey, err := s.MasterKeys.Load(folderPath)
	if err != nil {
		return err
	}

	index, err := s.Indexes.Load(folderPath, masterKey)
	if err != nil {
		return err
	}

	unlockablePaths, err := expandUnlockPaths(folderPath, index, paths)
	if err != nil {
		return err
	}

	for _, relativePath := range unlockablePaths {
		entry := index.Entries[relativePath]

		plaintext, err := s.Objects.Get(folderPath, masterKey, entry.ObjectID)
		if err != nil {
			return err
		}

		absolutePath := filepath.Join(folderPath, relativePath)
		_, err = os.Stat(absolutePath)
		if err == nil && !force {
			return fmt.Errorf("%s already exists. Pass --force to overwrite.", relativePath)
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}

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

func (s VaultService) ListPaths(folderPath string) ([]string, error) {
	masterKey, err := s.MasterKeys.Load(folderPath)
	if err != nil {
		return nil, err
	}

	index, err := s.Indexes.Load(folderPath, masterKey)
	if err != nil {
		return nil, err
	}

	paths := make([]string, 0, len(index.Entries))
	for path := range index.Entries {
		paths = append(paths, path)
	}

	sort.Strings(paths)
	return paths, nil
}

func expandLockPaths(folderPath string, paths []string) ([]string, error) {
	out := make([]string, 0)
	seen := map[string]bool{}

	for _, path := range paths {
		relativePath, err := normalizeRelativePath(folderPath, path)
		if err != nil {
			return nil, err
		}

		absolutePath := filepath.Join(folderPath, relativePath)
		info, err := os.Stat(absolutePath)
		if err != nil {
			return nil, err
		}

		if !info.IsDir() {
			if !seen[relativePath] {
				out = append(out, relativePath)
				seen[relativePath] = true
			}
			continue
		}

		err = filepath.WalkDir(absolutePath, func(currentPath string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}

			currentRelativePath, err := filepath.Rel(folderPath, currentPath)
			if err != nil {
				return err
			}
			currentRelativePath = filepath.Clean(currentRelativePath)
			if !seen[currentRelativePath] {
				out = append(out, currentRelativePath)
				seen[currentRelativePath] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	sort.Strings(out)
	return out, nil
}

func expandUnlockPaths(folderPath string, index *Index, paths []string) ([]string, error) {
	out := make([]string, 0)
	seen := map[string]bool{}

	for _, path := range paths {
		relativePath, err := normalizeRelativePath(folderPath, path)
		if err != nil {
			return nil, err
		}

		if _, ok := index.Entries[relativePath]; ok {
			if !seen[relativePath] {
				out = append(out, relativePath)
				seen[relativePath] = true
			}
			continue
		}

		prefix := relativePath + string(filepath.Separator)
		matched := false
		for indexedPath := range index.Entries {
			if strings.HasPrefix(indexedPath, prefix) {
				if !seen[indexedPath] {
					out = append(out, indexedPath)
					seen[indexedPath] = true
				}
				matched = true
			}
		}
		if !matched {
			return nil, fmt.Errorf("%s is not locked.", relativePath)
		}
	}

	sort.Strings(out)
	return out, nil
}

func pruneEmptyParentDirs(folderPath string, relativePath string) error {
	currentPath := filepath.Dir(filepath.Join(folderPath, relativePath))
	cleanFolderPath := filepath.Clean(folderPath)

	for currentPath != cleanFolderPath && currentPath != "." {
		err := os.Remove(currentPath)
		if err == nil {
			currentPath = filepath.Dir(currentPath)
			continue
		}
		if os.IsNotExist(err) {
			currentPath = filepath.Dir(currentPath)
			continue
		}
		if isDirectoryNotEmptyError(err) {
			return nil
		}
		return err
	}

	return nil
}

func isDirectoryNotEmptyError(err error) bool {
	return errors.Is(err, os.ErrExist) || strings.Contains(err.Error(), "directory not empty")
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
