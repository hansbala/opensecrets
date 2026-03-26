package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCleanStoreDir(t *testing.T) {
	t.Run("accepts relative store dir", func(t *testing.T) {
		storeDir, err := cleanStoreDir(".opensecrets")
		require.NoError(t, err)
		require.Equal(t, ".opensecrets", storeDir)
	})

	t.Run("rejects empty store dir", func(t *testing.T) {
		storeDir, err := cleanStoreDir("   ")
		require.Error(t, err)
		require.Empty(t, storeDir)
		require.EqualError(t, err, "store-dir must not be empty")
	})

	t.Run("rejects absolute store dir", func(t *testing.T) {
		storeDir, err := cleanStoreDir("/tmp/opensecrets")
		require.Error(t, err)
		require.Empty(t, storeDir)
		require.EqualError(t, err, "store-dir must be relative to the current folder")
	})

	t.Run("rejects current folder", func(t *testing.T) {
		storeDir, err := cleanStoreDir(".")
		require.Error(t, err)
		require.Empty(t, storeDir)
		require.EqualError(t, err, "store-dir must not be the current folder")
	})
}

func TestInitFolder(t *testing.T) {
	t.Run("creates metadata layout and config", func(t *testing.T) {
		folderPath := t.TempDir()

		err := initFolder(folderPath, cStoreDir)
		require.NoError(t, err)

		require.DirExists(t, storeRootPath(folderPath, cStoreDir))
		require.DirExists(t, storeObjectsPath(folderPath, cStoreDir))
		require.FileExists(t, configPath(folderPath, cStoreDir))

		configContents, err := os.ReadFile(configPath(folderPath, cStoreDir))
		require.NoError(t, err)
		require.Equal(t, buildConfigContents(cStoreDir), string(configContents))
	})

	t.Run("rejects reinitialization", func(t *testing.T) {
		folderPath := t.TempDir()

		err := initFolder(folderPath, cStoreDir)
		require.NoError(t, err)

		err = initFolder(folderPath, cStoreDir)
		require.EqualError(t, err, "init: folder already initialized at "+filepath.Join(folderPath, cStoreDir, cConfigFile))
	})
}
