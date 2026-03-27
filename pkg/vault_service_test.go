package opensecrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVaultService(t *testing.T) {
	t.Run("locks and unlocks a file", func(t *testing.T) {
		folderPath := t.TempDir()
		userConfigDir := t.TempDir()
		filePath := filepath.Join(folderPath, "secrets", "prod.env")
		err := os.MkdirAll(filepath.Dir(filePath), cDirPerm)
		require.NoError(t, err)

		originalContents := []byte("API_KEY=secret")
		err = os.WriteFile(filePath, originalContents, 0o600)
		require.NoError(t, err)

		masterKey, err := randomBytes(32)
		require.NoError(t, err)

		masterKeys := NewFilesystemMasterKeyManager(userConfigDir)
		err = masterKeys.Store(folderPath, masterKey)
		require.NoError(t, err)

		service := NewVaultService(
			masterKeys,
			NewFilesystemIndexStore(),
			NewFilesystemObjectStore(),
		)

		err = service.LockPaths(folderPath, []string{"secrets/prod.env"}, false, false)
		require.NoError(t, err)
		require.NoFileExists(t, filePath)

		index, err := NewFilesystemIndexStore().Load(folderPath, masterKey)
		require.NoError(t, err)
		require.Contains(t, index.Entries, "secrets/prod.env")

		err = service.UnlockPaths(folderPath, []string{"secrets/prod.env"}, false)
		require.NoError(t, err)

		restoredContents, err := os.ReadFile(filePath)
		require.NoError(t, err)
		require.Equal(t, originalContents, restoredContents)
	})

	t.Run("lists locked files in sorted order", func(t *testing.T) {
		folderPath := t.TempDir()
		userConfigDir := t.TempDir()
		masterKey, err := randomBytes(32)
		require.NoError(t, err)

		masterKeys := NewFilesystemMasterKeyManager(userConfigDir)
		err = masterKeys.Store(folderPath, masterKey)
		require.NoError(t, err)

		service := NewVaultService(
			masterKeys,
			NewFilesystemIndexStore(),
			NewFilesystemObjectStore(),
		)

		index := &Index{
			Entries: map[string]IndexEntry{
				"z.txt": {ObjectID: "z"},
				"a.txt": {ObjectID: "a"},
			},
		}
		err = NewFilesystemIndexStore().Save(folderPath, masterKey, index)
		require.NoError(t, err)

		paths, err := service.ListPaths(folderPath)
		require.NoError(t, err)
		require.Equal(t, []string{"a.txt", "z.txt"}, paths)
	})

	t.Run("refuses to overwrite existing plaintext on unlock without force", func(t *testing.T) {
		folderPath := t.TempDir()
		userConfigDir := t.TempDir()
		filePath := filepath.Join(folderPath, "file.txt")
		err := os.WriteFile(filePath, []byte("original"), 0o600)
		require.NoError(t, err)

		masterKey, err := randomBytes(32)
		require.NoError(t, err)

		masterKeys := NewFilesystemMasterKeyManager(userConfigDir)
		err = masterKeys.Store(folderPath, masterKey)
		require.NoError(t, err)

		service := NewVaultService(
			masterKeys,
			NewFilesystemIndexStore(),
			NewFilesystemObjectStore(),
		)

		err = service.LockPaths(folderPath, []string{"file.txt"}, true, false)
		require.NoError(t, err)

		err = os.WriteFile(filePath, []byte("local edit"), 0o600)
		require.NoError(t, err)

		err = service.UnlockPaths(folderPath, []string{"file.txt"}, false)
		require.EqualError(t, err, "file.txt already exists. Pass --force to overwrite.")

		contents, err := os.ReadFile(filePath)
		require.NoError(t, err)
		require.Equal(t, []byte("local edit"), contents)
	})

	t.Run("refuses to overwrite existing locked entry on lock without force", func(t *testing.T) {
		folderPath := t.TempDir()
		userConfigDir := t.TempDir()
		filePath := filepath.Join(folderPath, "file.txt")
		err := os.WriteFile(filePath, []byte("original"), 0o600)
		require.NoError(t, err)

		masterKey, err := randomBytes(32)
		require.NoError(t, err)

		masterKeys := NewFilesystemMasterKeyManager(userConfigDir)
		err = masterKeys.Store(folderPath, masterKey)
		require.NoError(t, err)

		service := NewVaultService(
			masterKeys,
			NewFilesystemIndexStore(),
			NewFilesystemObjectStore(),
		)

		err = service.LockPaths(folderPath, []string{"file.txt"}, true, false)
		require.NoError(t, err)

		err = service.LockPaths(folderPath, []string{"file.txt"}, true, false)
		require.EqualError(t, err, "file.txt is already locked. Pass --force to overwrite.")
	})

	t.Run("force allows overwrite on unlock", func(t *testing.T) {
		folderPath := t.TempDir()
		userConfigDir := t.TempDir()
		filePath := filepath.Join(folderPath, "file.txt")
		err := os.WriteFile(filePath, []byte("original"), 0o600)
		require.NoError(t, err)

		masterKey, err := randomBytes(32)
		require.NoError(t, err)

		masterKeys := NewFilesystemMasterKeyManager(userConfigDir)
		err = masterKeys.Store(folderPath, masterKey)
		require.NoError(t, err)

		service := NewVaultService(
			masterKeys,
			NewFilesystemIndexStore(),
			NewFilesystemObjectStore(),
		)

		err = service.LockPaths(folderPath, []string{"file.txt"}, true, false)
		require.NoError(t, err)

		err = os.WriteFile(filePath, []byte("local edit"), 0o600)
		require.NoError(t, err)

		err = service.UnlockPaths(folderPath, []string{"file.txt"}, true)
		require.NoError(t, err)

		contents, err := os.ReadFile(filePath)
		require.NoError(t, err)
		require.Equal(t, []byte("original"), contents)
	})
}
