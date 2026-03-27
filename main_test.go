package main

import (
	"os"
	"path/filepath"
	"testing"

	opkg "github.com/hansbala/opensecrets/pkg"
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
		masterKeyManager := opkg.NewFilesystemMasterKeyManager(userConfigDir)

		err := initFolder(folderPath, password)
		require.NoError(t, err)

		err = unlockFolder(folderPath, masterKeyManager, password)
		require.NoError(t, err)

		sessionFilePath := opkg.SessionPathForFolder(userConfigDir, folderPath)
		require.FileExists(t, sessionFilePath)

		masterKey, err := masterKeyManager.Load(folderPath)
		require.NoError(t, err)
		require.Len(t, masterKey, cMasterKeyLen)
	})

	t.Run("rejects wrong password", func(t *testing.T) {
		folderPath := t.TempDir()
		userConfigDir := t.TempDir()
		masterKeyManager := opkg.NewFilesystemMasterKeyManager(userConfigDir)

		err := initFolder(folderPath, "correct horse battery")
		require.NoError(t, err)

		err = unlockFolder(folderPath, masterKeyManager, "wrong password")
		require.EqualError(t, err, "invalid password")
	})

	t.Run("rejects uninitialized folder", func(t *testing.T) {
		masterKeyManager := opkg.NewFilesystemMasterKeyManager(t.TempDir())
		err := unlockFolder(t.TempDir(), masterKeyManager, "correct horse battery")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unlock: folder is not initialized")
	})
}

func TestFilesystemSessionLifecycle(t *testing.T) {
	t.Run("clear removes stored master key", func(t *testing.T) {
		userConfigDir := t.TempDir()
		folderPath := t.TempDir()
		password := "correct horse battery"
		masterKeyManager := opkg.NewFilesystemMasterKeyManager(userConfigDir)

		err := initFolder(folderPath, password)
		require.NoError(t, err)

		err = unlockFolder(folderPath, masterKeyManager, password)
		require.NoError(t, err)

		_, err = masterKeyManager.Load(folderPath)
		require.NoError(t, err)

		err = masterKeyManager.Clear(folderPath)
		require.NoError(t, err)

		_, err = masterKeyManager.Load(folderPath)
		require.Error(t, err)
		require.True(t, os.IsNotExist(err))
	})

	t.Run("clear is safe when no session exists", func(t *testing.T) {
		userConfigDir := t.TempDir()
		folderPath := t.TempDir()
		masterKeyManager := opkg.NewFilesystemMasterKeyManager(userConfigDir)

		err := masterKeyManager.Clear(folderPath)
		require.NoError(t, err)
	})
}
