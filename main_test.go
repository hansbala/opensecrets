package main

import (
	"bytes"
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

func TestRunLockAndUnlockPath(t *testing.T) {
	folderPath := t.TempDir()
	userConfigDir := t.TempDir()
	password := "correct horse battery"
	filePath := filepath.Join(folderPath, "secrets", "prod.env")
	err := os.MkdirAll(filepath.Dir(filePath), cDirPerm)
	require.NoError(t, err)

	originalContents := []byte("API_KEY=secret")
	err = os.WriteFile(filePath, originalContents, 0o600)
	require.NoError(t, err)

	err = initFolder(folderPath, password)
	require.NoError(t, err)

	filesystemMasterKeyManager := opkg.NewFilesystemMasterKeyManager(userConfigDir)

	originalNewMasterKeyManager := cNewMasterKeyManager
	originalNewVaultService := cNewVaultService
	cNewMasterKeyManager = func() (opkg.MasterKeyManager, error) {
		return filesystemMasterKeyManager, nil
	}
	cNewVaultService = func() (opkg.VaultService, error) {
		return opkg.NewVaultService(
			filesystemMasterKeyManager,
			opkg.NewFilesystemIndexStore(),
			opkg.NewFilesystemObjectStore(),
		), nil
	}
	defer func() {
		cNewMasterKeyManager = originalNewMasterKeyManager
		cNewVaultService = originalNewVaultService
	}()

	originalWorkingDir, err := os.Getwd()
	require.NoError(t, err)
	err = os.Chdir(folderPath)
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(originalWorkingDir)
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err = unlockFolder(folderPath, filesystemMasterKeyManager, password)
	require.NoError(t, err)

	err = run([]string{"lock", "secrets/prod.env"}, &stdout, &stderr)
	require.NoError(t, err)
	require.NoFileExists(t, filePath)

	stdout.Reset()
	stderr.Reset()

	err = run([]string{"unlock", "secrets/prod.env"}, &stdout, &stderr)
	require.NoError(t, err)

	restoredContents, err := os.ReadFile(filePath)
	require.NoError(t, err)
	require.Equal(t, originalContents, restoredContents)
}

func TestRunLockWithKeepAfterPath(t *testing.T) {
	folderPath := t.TempDir()
	userConfigDir := t.TempDir()
	password := "correct horse battery"
	filePath := filepath.Join(folderPath, "file1.txt")
	err := os.WriteFile(filePath, []byte("hello"), 0o600)
	require.NoError(t, err)

	err = initFolder(folderPath, password)
	require.NoError(t, err)

	filesystemMasterKeyManager := opkg.NewFilesystemMasterKeyManager(userConfigDir)
	err = unlockFolder(folderPath, filesystemMasterKeyManager, password)
	require.NoError(t, err)

	originalNewMasterKeyManager := cNewMasterKeyManager
	originalNewVaultService := cNewVaultService
	cNewMasterKeyManager = func() (opkg.MasterKeyManager, error) {
		return filesystemMasterKeyManager, nil
	}
	cNewVaultService = func() (opkg.VaultService, error) {
		return opkg.NewVaultService(
			filesystemMasterKeyManager,
			opkg.NewFilesystemIndexStore(),
			opkg.NewFilesystemObjectStore(),
		), nil
	}
	defer func() {
		cNewMasterKeyManager = originalNewMasterKeyManager
		cNewVaultService = originalNewVaultService
	}()

	originalWorkingDir, err := os.Getwd()
	require.NoError(t, err)
	err = os.Chdir(folderPath)
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(originalWorkingDir)
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err = run([]string{"lock", "file1.txt", "--keep"}, &stdout, &stderr)
	require.NoError(t, err)
	require.FileExists(t, filePath)
}

func TestRunUnlockRefusesOverwriteWithoutForce(t *testing.T) {
	folderPath := t.TempDir()
	userConfigDir := t.TempDir()
	password := "correct horse battery"
	filePath := filepath.Join(folderPath, "file1.txt")
	err := os.WriteFile(filePath, []byte("original"), 0o600)
	require.NoError(t, err)

	err = initFolder(folderPath, password)
	require.NoError(t, err)

	filesystemMasterKeyManager := opkg.NewFilesystemMasterKeyManager(userConfigDir)
	err = unlockFolder(folderPath, filesystemMasterKeyManager, password)
	require.NoError(t, err)

	originalNewMasterKeyManager := cNewMasterKeyManager
	originalNewVaultService := cNewVaultService
	cNewMasterKeyManager = func() (opkg.MasterKeyManager, error) {
		return filesystemMasterKeyManager, nil
	}
	cNewVaultService = func() (opkg.VaultService, error) {
		return opkg.NewVaultService(
			filesystemMasterKeyManager,
			opkg.NewFilesystemIndexStore(),
			opkg.NewFilesystemObjectStore(),
		), nil
	}
	defer func() {
		cNewMasterKeyManager = originalNewMasterKeyManager
		cNewVaultService = originalNewVaultService
	}()

	originalWorkingDir, err := os.Getwd()
	require.NoError(t, err)
	err = os.Chdir(folderPath)
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(originalWorkingDir)
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err = run([]string{"lock", "file1.txt", "--keep"}, &stdout, &stderr)
	require.NoError(t, err)

	err = os.WriteFile(filePath, []byte("local edit"), 0o600)
	require.NoError(t, err)

	stdout.Reset()
	stderr.Reset()

	err = run([]string{"unlock", "file1.txt"}, &stdout, &stderr)
	require.EqualError(t, err, "unlock: file1.txt already exists. Pass --force to overwrite.")
}

func TestRunForceAfterPath(t *testing.T) {
	folderPath := t.TempDir()
	userConfigDir := t.TempDir()
	password := "correct horse battery"
	filePath := filepath.Join(folderPath, "file1.txt")
	err := os.WriteFile(filePath, []byte("original"), 0o600)
	require.NoError(t, err)

	err = initFolder(folderPath, password)
	require.NoError(t, err)

	filesystemMasterKeyManager := opkg.NewFilesystemMasterKeyManager(userConfigDir)
	err = unlockFolder(folderPath, filesystemMasterKeyManager, password)
	require.NoError(t, err)

	originalNewMasterKeyManager := cNewMasterKeyManager
	originalNewVaultService := cNewVaultService
	cNewMasterKeyManager = func() (opkg.MasterKeyManager, error) {
		return filesystemMasterKeyManager, nil
	}
	cNewVaultService = func() (opkg.VaultService, error) {
		return opkg.NewVaultService(
			filesystemMasterKeyManager,
			opkg.NewFilesystemIndexStore(),
			opkg.NewFilesystemObjectStore(),
		), nil
	}
	defer func() {
		cNewMasterKeyManager = originalNewMasterKeyManager
		cNewVaultService = originalNewVaultService
	}()

	originalWorkingDir, err := os.Getwd()
	require.NoError(t, err)
	err = os.Chdir(folderPath)
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(originalWorkingDir)
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err = run([]string{"lock", "file1.txt", "--keep"}, &stdout, &stderr)
	require.NoError(t, err)

	err = os.WriteFile(filePath, []byte("updated"), 0o600)
	require.NoError(t, err)

	stdout.Reset()
	stderr.Reset()

	err = run([]string{"lock", "file1.txt", "--force", "--keep"}, &stdout, &stderr)
	require.NoError(t, err)

	err = os.WriteFile(filePath, []byte("local edit"), 0o600)
	require.NoError(t, err)

	stdout.Reset()
	stderr.Reset()

	err = run([]string{"unlock", "file1.txt", "--force"}, &stdout, &stderr)
	require.NoError(t, err)

	contents, err := os.ReadFile(filePath)
	require.NoError(t, err)
	require.Equal(t, []byte("updated"), contents)
}

func TestVersionOutput(t *testing.T) {
	originalVersion := cVersion
	cVersion = "test-version"
	defer func() {
		cVersion = originalVersion
	}()

	t.Run("version command", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		err := run([]string{"version"}, &stdout, &stderr)
		require.NoError(t, err)
		require.Equal(t, "opensecrets test-version\n", stdout.String())
		require.Empty(t, stderr.String())
	})

	t.Run("top level version flag", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		err := run([]string{"--version"}, &stdout, &stderr)
		require.NoError(t, err)
		require.Equal(t, "opensecrets test-version\n", stdout.String())
		require.Empty(t, stderr.String())
	})
}

func TestRunList(t *testing.T) {
	folderPath := t.TempDir()
	userConfigDir := t.TempDir()
	masterKey, err := randomBytes(32)
	require.NoError(t, err)

	err = initFolder(folderPath, "correct horse battery")
	require.NoError(t, err)

	filesystemMasterKeyManager := opkg.NewFilesystemMasterKeyManager(userConfigDir)
	err = filesystemMasterKeyManager.Store(folderPath, masterKey)
	require.NoError(t, err)

	indexStore := opkg.NewFilesystemIndexStore()
	err = indexStore.Save(folderPath, masterKey, &opkg.Index{
		Entries: map[string]opkg.IndexEntry{
			"z.txt": {ObjectID: "z"},
			"a.txt": {ObjectID: "a"},
		},
	})
	require.NoError(t, err)

	originalNewVaultService := cNewVaultService
	cNewVaultService = func() (opkg.VaultService, error) {
		return opkg.NewVaultService(
			filesystemMasterKeyManager,
			indexStore,
			opkg.NewFilesystemObjectStore(),
		), nil
	}
	defer func() {
		cNewVaultService = originalNewVaultService
	}()

	originalWorkingDir, err := os.Getwd()
	require.NoError(t, err)
	err = os.Chdir(folderPath)
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(originalWorkingDir)
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err = run([]string{"ls"}, &stdout, &stderr)
	require.NoError(t, err)
	require.Equal(t, "a.txt\nz.txt\n", stdout.String())
	require.Empty(t, stderr.String())
}

func TestRunLockAndUnlockDirectory(t *testing.T) {
	folderPath := t.TempDir()
	userConfigDir := t.TempDir()
	password := "correct horse battery"
	fileOnePath := filepath.Join(folderPath, "docs", "a.txt")
	fileTwoPath := filepath.Join(folderPath, "docs", "nested", "b.txt")
	err := os.MkdirAll(filepath.Dir(fileTwoPath), cDirPerm)
	require.NoError(t, err)

	err = os.WriteFile(fileOnePath, []byte("a"), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(fileTwoPath, []byte("b"), 0o600)
	require.NoError(t, err)

	err = initFolder(folderPath, password)
	require.NoError(t, err)

	filesystemMasterKeyManager := opkg.NewFilesystemMasterKeyManager(userConfigDir)
	err = unlockFolder(folderPath, filesystemMasterKeyManager, password)
	require.NoError(t, err)

	originalNewMasterKeyManager := cNewMasterKeyManager
	originalNewVaultService := cNewVaultService
	cNewMasterKeyManager = func() (opkg.MasterKeyManager, error) {
		return filesystemMasterKeyManager, nil
	}
	cNewVaultService = func() (opkg.VaultService, error) {
		return opkg.NewVaultService(
			filesystemMasterKeyManager,
			opkg.NewFilesystemIndexStore(),
			opkg.NewFilesystemObjectStore(),
		), nil
	}
	defer func() {
		cNewMasterKeyManager = originalNewMasterKeyManager
		cNewVaultService = originalNewVaultService
	}()

	originalWorkingDir, err := os.Getwd()
	require.NoError(t, err)
	err = os.Chdir(folderPath)
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(originalWorkingDir)
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err = run([]string{"lock", "docs"}, &stdout, &stderr)
	require.NoError(t, err)
	require.NoFileExists(t, fileOnePath)
	require.NoFileExists(t, fileTwoPath)

	stdout.Reset()
	stderr.Reset()

	err = run([]string{"unlock", "docs"}, &stdout, &stderr)
	require.NoError(t, err)

	fileOneContents, err := os.ReadFile(fileOnePath)
	require.NoError(t, err)
	require.Equal(t, []byte("a"), fileOneContents)

	fileTwoContents, err := os.ReadFile(fileTwoPath)
	require.NoError(t, err)
	require.Equal(t, []byte("b"), fileTwoContents)
}

func TestRunLockDirectoryPrunesEmptyDirs(t *testing.T) {
	folderPath := t.TempDir()
	userConfigDir := t.TempDir()
	password := "correct horse battery"
	filePath := filepath.Join(folderPath, "test_dir", "nested", "file.txt")
	err := os.MkdirAll(filepath.Dir(filePath), cDirPerm)
	require.NoError(t, err)

	err = os.WriteFile(filePath, []byte("hello"), 0o600)
	require.NoError(t, err)

	err = initFolder(folderPath, password)
	require.NoError(t, err)

	filesystemMasterKeyManager := opkg.NewFilesystemMasterKeyManager(userConfigDir)
	err = unlockFolder(folderPath, filesystemMasterKeyManager, password)
	require.NoError(t, err)

	originalNewMasterKeyManager := cNewMasterKeyManager
	originalNewVaultService := cNewVaultService
	cNewMasterKeyManager = func() (opkg.MasterKeyManager, error) {
		return filesystemMasterKeyManager, nil
	}
	cNewVaultService = func() (opkg.VaultService, error) {
		return opkg.NewVaultService(
			filesystemMasterKeyManager,
			opkg.NewFilesystemIndexStore(),
			opkg.NewFilesystemObjectStore(),
		), nil
	}
	defer func() {
		cNewMasterKeyManager = originalNewMasterKeyManager
		cNewVaultService = originalNewVaultService
	}()

	originalWorkingDir, err := os.Getwd()
	require.NoError(t, err)
	err = os.Chdir(folderPath)
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(originalWorkingDir)
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err = run([]string{"lock", "test_dir"}, &stdout, &stderr)
	require.NoError(t, err)
	require.NoDirExists(t, filepath.Join(folderPath, "test_dir"))
}
