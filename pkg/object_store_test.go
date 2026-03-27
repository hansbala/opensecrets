package opensecrets

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilesystemObjectStore(t *testing.T) {
	folderPath := t.TempDir()
	masterKey, err := randomBytes(32)
	require.NoError(t, err)

	store := NewFilesystemObjectStore()
	plaintext := []byte("super secret data")

	objectID, err := store.Put(folderPath, masterKey, plaintext)
	require.NoError(t, err)
	require.NotEmpty(t, objectID)

	loadedPlaintext, err := store.Get(folderPath, masterKey, objectID)
	require.NoError(t, err)
	require.Equal(t, plaintext, loadedPlaintext)

	err = store.Delete(folderPath, objectID)
	require.NoError(t, err)
}
