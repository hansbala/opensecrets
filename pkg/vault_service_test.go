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

		err = service.LockPaths(folderPath, []string{"secrets/prod.env"}, false)
		require.NoError(t, err)
		require.NoFileExists(t, filePath)

		index, err := NewFilesystemIndexStore().Load(folderPath, masterKey)
		require.NoError(t, err)
		require.Contains(t, index.Entries, "secrets/prod.env")

		err = service.UnlockPaths(folderPath, []string{"secrets/prod.env"})
		require.NoError(t, err)

		restoredContents, err := os.ReadFile(filePath)
		require.NoError(t, err)
		require.Equal(t, originalContents, restoredContents)
	})
}
