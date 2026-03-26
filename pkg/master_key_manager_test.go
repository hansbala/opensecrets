package opensecrets

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilesystemMasterKeyManager(t *testing.T) {
	userConfigDir := t.TempDir()
	folderPath := t.TempDir()
	manager := NewFilesystemMasterKeyManager(userConfigDir)
	masterKey := []byte("test-master-key")

	err := manager.Store(folderPath, masterKey)
	require.NoError(t, err)

	sessionPath := SessionPathForFolder(userConfigDir, folderPath)
	require.FileExists(t, sessionPath)

	loadedMasterKey, err := manager.Load(folderPath)
	require.NoError(t, err)
	require.Equal(t, masterKey, loadedMasterKey)

	err = manager.Clear(folderPath)
	require.NoError(t, err)

	_, err = os.Stat(sessionPath)
	require.True(t, os.IsNotExist(err))
}
