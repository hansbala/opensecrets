package opensecrets

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilesystemIndexStore(t *testing.T) {
	folderPath := t.TempDir()
	masterKey, err := randomBytes(32)
	require.NoError(t, err)

	store := NewFilesystemIndexStore()

	index, err := store.Load(folderPath, masterKey)
	require.NoError(t, err)
	require.Equal(t, cIndexVersion, index.Version)
	require.Empty(t, index.Entries)

	index.Entries["secrets/prod.env"] = IndexEntry{
		ObjectID: "object-1",
		Size:     123,
		Mode:     0o600,
	}

	err = store.Save(folderPath, masterKey, index)
	require.NoError(t, err)

	loadedIndex, err := store.Load(folderPath, masterKey)
	require.NoError(t, err)
	require.Equal(t, index, loadedIndex)
}
