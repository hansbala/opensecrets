package opensecrets

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	cToolName       = "opensecrets"
	cDirPerm        = 0o700
	cFilePerm       = 0o600
	cSessionDirName = "sessions"
	cSessionFileExt = ".json"
)

type MasterKeyManager interface {
	// Store persists the unlocked master key for a folder in the active session backend.
	Store(folderPath string, masterKey []byte) error
	// Load retrieves the unlocked master key for a folder from the active session backend.
	Load(folderPath string) ([]byte, error)
	// Clear removes the unlocked master key for a folder from the active session backend.
	Clear(folderPath string) error
}

// FilesystemMasterKeyManager stores unlocked master keys in machine-local session files.
type FilesystemMasterKeyManager struct {
	userConfigDir string
}

type sessionState struct {
	FolderPath string `json:"folder_path"`
	CreatedAt  string `json:"created_at"`
	MasterKey  []byte `json:"master_key"`
}

func NewFilesystemMasterKeyManager(userConfigDir string) MasterKeyManager {
	return FilesystemMasterKeyManager{
		userConfigDir: userConfigDir,
	}
}

// SessionPathForFolder returns the filesystem session path used for a folder.
func SessionPathForFolder(userConfigDir string, folderPath string) string {
	digest := sha256.Sum256([]byte(folderPath))
	sessionName := fmt.Sprintf("%x%s", digest, cSessionFileExt)
	return filepath.Join(userConfigDir, cToolName, cSessionDirName, sessionName)
}

func (m FilesystemMasterKeyManager) Store(folderPath string, masterKey []byte) error {
	sessionPath := SessionPathForFolder(m.userConfigDir, folderPath)
	err := os.MkdirAll(filepath.Dir(sessionPath), cDirPerm)
	if err != nil {
		return err
	}

	state := sessionState{
		FolderPath: folderPath,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		MasterKey:  masterKey,
	}

	return writeJSONFile(sessionPath, state, cFilePerm)
}

func (m FilesystemMasterKeyManager) Load(folderPath string) ([]byte, error) {
	sessionPath := SessionPathForFolder(m.userConfigDir, folderPath)
	contents, err := os.ReadFile(sessionPath)
	if err != nil {
		return nil, err
	}

	var state sessionState
	err = json.Unmarshal(contents, &state)
	if err != nil {
		return nil, err
	}

	return state.MasterKey, nil
}

func (m FilesystemMasterKeyManager) Clear(folderPath string) error {
	sessionPath := SessionPathForFolder(m.userConfigDir, folderPath)
	err := os.Remove(sessionPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

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
