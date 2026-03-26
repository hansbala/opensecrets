package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitFolder(t *testing.T) {
	t.Run("creates metadata layout and config", func(t *testing.T) {
		folderPath := t.TempDir()

		err := initFolder(folderPath, "correct horse battery")
		require.NoError(t, err)

		require.DirExists(t, storeRootPath(folderPath))
		require.DirExists(t, storeObjectsPath(folderPath))
		require.FileExists(t, configPath(folderPath))
		require.FileExists(t, masterKeyPath(folderPath))

		configContents, err := os.ReadFile(configPath(folderPath))
		require.NoError(t, err)
		require.Equal(t, buildConfigContents(), string(configContents))

		envelope, err := readMasterKeyEnvelope(folderPath)
		require.NoError(t, err)
		require.Equal(t, cKDFName, envelope.KDF)
		require.Equal(t, cCipherName, envelope.Cipher)
		require.NotEmpty(t, envelope.Salt)
		require.NotEmpty(t, envelope.Nonce)
		require.NotEmpty(t, envelope.Ciphertext)
	})

	t.Run("rejects reinitialization", func(t *testing.T) {
		folderPath := t.TempDir()

		err := initFolder(folderPath, "correct horse battery")
		require.NoError(t, err)

		err = initFolder(folderPath, "correct horse battery")
		require.EqualError(t, err, "init: folder already initialized at "+filepath.Join(folderPath, cStoreDir, cConfigFile))
	})
}

func TestFindFolderRoot(t *testing.T) {
	t.Run("finds root from nested folder", func(t *testing.T) {
		folderPath := t.TempDir()
		err := initFolder(folderPath, "correct horse battery")
		require.NoError(t, err)

		nestedPath := filepath.Join(folderPath, "a", "b", "c")
		err = os.MkdirAll(nestedPath, cDirPerm)
		require.NoError(t, err)

		foundFolderPath, err := findFolderRoot(nestedPath)
		require.NoError(t, err)
		require.Equal(t, folderPath, foundFolderPath)
	})

	t.Run("returns error when no folder is initialized", func(t *testing.T) {
		_, err := findFolderRoot(t.TempDir())
		require.EqualError(t, err, "find folder root: no .opensecrets/config.toml found")
	})
}

func TestUnlockFolder(t *testing.T) {
	t.Run("creates local session state", func(t *testing.T) {
		folderPath := t.TempDir()
		userConfigDir := t.TempDir()
		password := "correct horse battery"

		err := initFolder(folderPath, password)
		require.NoError(t, err)

		err = unlockFolder(folderPath, userConfigDir, password)
		require.NoError(t, err)

		sessionFilePath := sessionPath(userConfigDir, folderPath)
		require.FileExists(t, sessionFilePath)

		sessionContents, err := os.ReadFile(sessionFilePath)
		require.NoError(t, err)

		var state sessionState
		err = json.Unmarshal(sessionContents, &state)
		require.NoError(t, err)
		require.Equal(t, folderPath, state.FolderPath)
		require.NotEmpty(t, state.CreatedAt)
		require.Len(t, state.MasterKey, cMasterKeyLen)
	})

	t.Run("rejects wrong password", func(t *testing.T) {
		folderPath := t.TempDir()
		userConfigDir := t.TempDir()

		err := initFolder(folderPath, "correct horse battery")
		require.NoError(t, err)

		err = unlockFolder(folderPath, userConfigDir, "wrong password")
		require.EqualError(t, err, "unlock: invalid password")
	})

	t.Run("rejects uninitialized folder", func(t *testing.T) {
		err := unlockFolder(t.TempDir(), t.TempDir(), "correct horse battery")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unlock: folder is not initialized")
	})
}
