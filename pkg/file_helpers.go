package opensecrets

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	cDirPerm  = 0o700
	cFilePerm = 0o600
)

func writeJSONFile(path string, value any, perm os.FileMode) error {
	contents, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}

	return writeFileAtomically(path, append(contents, '\n'), perm)
}

func writeFileAtomically(path string, contents []byte, perm os.FileMode) error {
	parentDir := filepath.Dir(path)
	tempFile, err := os.CreateTemp(parentDir, "opensecrets-*.tmp")
	if err != nil {
		return err
	}

	tempPath := tempFile.Name()
	defer func() {
		_ = os.Remove(tempPath)
	}()

	err = tempFile.Chmod(perm)
	if err != nil {
		_ = tempFile.Close()
		return err
	}

	_, err = tempFile.Write(contents)
	if err != nil {
		_ = tempFile.Close()
		return err
	}

	err = tempFile.Close()
	if err != nil {
		return err
	}

	return os.Rename(tempPath, path)
}
