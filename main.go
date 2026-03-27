package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	opkg "github.com/hansbala/opensecrets/pkg"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	cToolName        = "opensecrets"
	cStoreDir        = ".opensecrets"
	cStoreSubdir     = "store"
	cConfigFile      = "config.toml"
	cMasterKeyFile   = "masterkey.enc"
	cConfigVersion   = 1
	cDirPerm         = 0o700
	cFilePerm        = 0o600
	cExitUsage       = 2
	cExitFailure     = 1
	cMasterKeyLen    = 32
	cWrapKeyLen      = 32
	cArgonTime       = 3
	cArgonMemory     = 64 * 1024
	cArgonThreads    = 4
	cKDFName         = "argon2id"
	cCipherName      = "xchacha20poly1305"
	cPasswordPrompt  = "Enter password to secure the vault: "
	cPasswordConfirm = "Confirm password: "
	cUnlockPrompt    = "Enter password to unlock vault: "
)

type command struct {
	name        string
	summary     string
	usageLine   string
	description string
}

var (
	cCommands = []command{
		{
			name:        "init",
			summary:     "Initialize a protected folder.",
			usageLine:   "opensecrets init [flags]",
			description: "Creates the .opensecrets metadata directory in the current folder and prepares it for encrypted storage.",
		},
		{
			name:        "unlock",
			summary:     "Start a session or unlock one or more paths.",
			usageLine:   "opensecrets unlock [flags] [path ...]",
			description: "With no paths, starts a local authenticated session. With one or more paths, unlocks the requested files or directories into the folder.",
		},
		{
			name:        "lock",
			summary:     "Lock one or more paths or close the current session.",
			usageLine:   "opensecrets lock [flags] [path ...]",
			description: "With one or more paths, writes those files or directories back into the encrypted store. With no paths, locks all tracked plaintext and clears the local session.",
		},
		{
			name:        "help",
			summary:     "Show general or command-specific help.",
			usageLine:   "opensecrets help [command]",
			description: "Prints top-level help or detailed help for a single command.",
		},
	}
	cNewMasterKeyManager = newMasterKeyManager
	cNewVaultService     = newVaultService
)

func main() {
	err := run(os.Args[1:], os.Stdout, os.Stderr)
	if err == nil {
		return
	}

	var usageErr *usageError
	if errors.As(err, &usageErr) {
		fmt.Fprintln(os.Stderr, usageErr.Error())
		os.Exit(cExitUsage)
	}

	fmt.Fprintln(os.Stderr, err)
	os.Exit(cExitFailure)
}

func run(args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		writeTopLevelUsage(stdout)
		return nil
	}

	switch args[0] {
	case "-h", "--help", "help":
		return runHelp(args[1:])
	}

	cmd, ok := findCommand(args[0])
	if !ok {
		writeTopLevelUsage(stderr)
		return &usageError{msg: fmt.Sprintf("unknown command %q", args[0])}
	}

	switch cmd.name {
	case "init":
		return runInit(args[1:])
	case "unlock":
		return runUnlock(args[1:])
	case "lock":
		return runLock(args[1:])
	case "help":
		return runHelp(args[1:])
	default:
		return &usageError{msg: fmt.Sprintf("unknown command %q", cmd.name)}
	}
}

type usageError struct {
	msg string
}

type masterKeyEnvelope struct {
	KDF        string `json:"kdf"`
	Cipher     string `json:"cipher"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func (e *usageError) Error() string {
	return e.msg
}

func runHelp(args []string) error {
	if len(args) == 0 {
		writeTopLevelUsage(os.Stdout)
		return nil
	}
	if len(args) > 1 {
		return &usageError{msg: "help accepts at most one command name"}
	}

	cmd, ok := findCommand(args[0])
	if !ok {
		return &usageError{msg: fmt.Sprintf("unknown command %q", args[0])}
	}

	writeCommandUsage(os.Stdout, cmd)
	return nil
}

func runInit(args []string) error {
	cmd, _ := findCommand("init")
	fs := newFlagSet(cmd)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return &usageError{msg: "init does not accept positional arguments"}
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve current directory: %w", err)
	}

	err = ensureFolderNotInitialized(cwd)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Setting up encrypted vault in %s\n", storeRootPath(cwd))

	password, err := promptNewPassword()
	if err != nil {
		return err
	}

	err = initFolder(cwd, password)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Initialized OpenSecrets in %s\n", cwd)

	return nil
}

func runUnlock(args []string) error {
	cmd, _ := findCommand("unlock")
	fs := newFlagSet(cmd)
	passwordStdin := fs.Bool("password-stdin", false, "Read the password from stdin when starting a session.")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	paths, err := cleanPaths(fs.Args())
	if err != nil {
		return err
	}

	if len(paths) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve current directory: %w", err)
		}

		folderPath, err := findFolderRoot(cwd)
		if err != nil {
			return err
		}

		masterKeyManager, err := cNewMasterKeyManager()
		if err != nil {
			return err
		}

		password := ""
		if *passwordStdin {
			password, err = readPasswordFromStdin()
		} else {
			password, err = readPassword(cUnlockPrompt)
		}
		if err != nil {
			return err
		}

		err = unlockFolder(folderPath, masterKeyManager, password)
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "Unlocked %s\n", folderPath)

		return nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve current directory: %w", err)
	}

	folderPath, err := findFolderRoot(cwd)
	if err != nil {
		return err
	}

	vaultService, err := cNewVaultService()
	if err != nil {
		return err
	}

	err = vaultService.UnlockPaths(folderPath, paths)
	if err != nil {
		return fmt.Errorf("unlock: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Unlocked %s\n", strings.Join(paths, ", "))

	return nil
}

func runLock(args []string) error {
	cmd, _ := findCommand("lock")
	fs := newFlagSet(cmd)
	keep := fs.Bool("keep", false, "Keep plaintext files after locking paths.")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	paths, err := cleanPaths(fs.Args())
	if err != nil {
		return err
	}

	if len(paths) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve current directory: %w", err)
		}

		folderPath, err := findFolderRoot(cwd)
		if err != nil {
			return err
		}

		masterKeyManager, err := cNewMasterKeyManager()
		if err != nil {
			return err
		}

		err = masterKeyManager.Clear(folderPath)
		if err != nil {
			return fmt.Errorf("lock: clear session master key: %w", err)
		}

		fmt.Fprintf(os.Stdout, "Locked %s\n", folderPath)

		return nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve current directory: %w", err)
	}

	folderPath, err := findFolderRoot(cwd)
	if err != nil {
		return err
	}

	vaultService, err := cNewVaultService()
	if err != nil {
		return err
	}

	err = vaultService.LockPaths(folderPath, paths, *keep)
	if err != nil {
		return fmt.Errorf("lock: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Locked %s\n", strings.Join(paths, ", "))

	return nil
}

func newFlagSet(cmd command) *flag.FlagSet {
	fs := flag.NewFlagSet(cmd.name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {
		writeCommandUsage(os.Stdout, cmd)
	}
	return fs
}

func cleanPaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			return nil, &usageError{msg: "path arguments must not be empty"}
		}
		out = append(out, filepath.Clean(path))
	}
	return out, nil
}

func formatPaths(paths []string) string {
	if len(paths) == 0 {
		return "(none)"
	}
	return strings.Join(paths, ", ")
}

func findCommand(name string) (command, bool) {
	for _, cmd := range cCommands {
		if cmd.name == name {
			return cmd, true
		}
	}
	return command{}, false
}

func notImplemented(cmdName, details, next string) error {
	return fmt.Errorf("%s: not implemented yet (%s); %s", cmdName, details, next)
}

func ensureFolderNotInitialized(folderPath string) error {
	configPath := configPath(folderPath)
	_, err := os.Stat(configPath)
	if err == nil {
		return fmt.Errorf("init: folder already initialized at %s", configPath)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("init: stat config: %w", err)
	}

	return nil
}

func initFolder(folderPath string, password string) error {
	err := ensureFolderNotInitialized(folderPath)
	if err != nil {
		return err
	}

	storeRootPath := storeRootPath(folderPath)
	storeObjectsPath := storeObjectsPath(folderPath)

	err = os.MkdirAll(storeObjectsPath, cDirPerm)
	if err != nil {
		return fmt.Errorf("init: create metadata directories: %w", err)
	}

	envelope, err := createMasterKeyEnvelope(password)
	if err != nil {
		return fmt.Errorf("init: create encrypted master key: %w", err)
	}

	err = writeJSONFile(masterKeyPath(folderPath), envelope, cFilePerm)
	if err != nil {
		return fmt.Errorf("init: write master key: %w", err)
	}

	configContents := buildConfigContents()
	err = writeFileAtomically(configPath(folderPath), []byte(configContents), cFilePerm)
	if err != nil {
		return fmt.Errorf("init: write config: %w", err)
	}

	err = os.Chmod(storeRootPath, cDirPerm)
	if err != nil {
		return fmt.Errorf("init: set metadata permissions: %w", err)
	}

	err = os.Chmod(storeObjectsPath, cDirPerm)
	if err != nil {
		return fmt.Errorf("init: set store permissions: %w", err)
	}

	return nil
}

func findFolderRoot(startPath string) (string, error) {
	cleanStartPath := filepath.Clean(startPath)
	info, err := os.Stat(cleanStartPath)
	if err != nil {
		return "", fmt.Errorf("find folder root: stat start path: %w", err)
	}

	currentPath := cleanStartPath
	if !info.IsDir() {
		currentPath = filepath.Dir(cleanStartPath)
	}

	for {
		_, err := os.Stat(configPath(currentPath))
		if err == nil {
			return currentPath, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("find folder root: stat config: %w", err)
		}

		parentPath := filepath.Dir(currentPath)
		if parentPath == currentPath {
			return "", fmt.Errorf("find folder root: no %s/%s found", cStoreDir, cConfigFile)
		}
		currentPath = parentPath
	}
}

func unlockFolder(folderPath string, masterKeyManager opkg.MasterKeyManager, password string) error {
	_, err := os.Stat(configPath(folderPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("unlock: folder is not initialized: %s", folderPath)
		}
		return fmt.Errorf("unlock: stat config: %w", err)
	}

	envelope, err := readMasterKeyEnvelope(folderPath)
	if err != nil {
		return fmt.Errorf("unlock: read master key: %w", err)
	}

	masterKey, err := decryptMasterKey(envelope, password)
	if err != nil {
		return errors.New("invalid password")
	}

	// TODO: Replace this filesystem-backed master key manager with OS keyring storage.
	err = masterKeyManager.Store(folderPath, masterKey)
	if err != nil {
		return fmt.Errorf("unlock: store session master key: %w", err)
	}

	return nil
}

func storeRootPath(folderPath string) string {
	return filepath.Join(folderPath, cStoreDir)
}

func storeObjectsPath(folderPath string) string {
	return filepath.Join(storeRootPath(folderPath), cStoreSubdir)
}

func configPath(folderPath string) string {
	return filepath.Join(storeRootPath(folderPath), cConfigFile)
}

func masterKeyPath(folderPath string) string {
	return filepath.Join(storeRootPath(folderPath), cMasterKeyFile)
}

func buildConfigContents() string {
	return strings.Join([]string{
		fmt.Sprintf("version = %d", cConfigVersion),
		fmt.Sprintf("kdf = %q", cKDFName),
		fmt.Sprintf("cipher = %q", cCipherName),
		"",
	}, "\n")
}

func createMasterKeyEnvelope(password string) (masterKeyEnvelope, error) {
	masterKey, err := randomBytes(cMasterKeyLen)
	if err != nil {
		return masterKeyEnvelope{}, err
	}

	salt, err := randomBytes(chacha20poly1305.KeySize)
	if err != nil {
		return masterKeyEnvelope{}, err
	}

	wrapKey := deriveWrapKey(password, salt)
	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return masterKeyEnvelope{}, err
	}

	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return masterKeyEnvelope{}, err
	}

	ciphertext := aead.Seal(nil, nonce, masterKey, nil)

	return masterKeyEnvelope{
		KDF:        cKDFName,
		Cipher:     cCipherName,
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

func readMasterKeyEnvelope(folderPath string) (masterKeyEnvelope, error) {
	var envelope masterKeyEnvelope

	contents, err := os.ReadFile(masterKeyPath(folderPath))
	if err != nil {
		return envelope, err
	}

	err = json.Unmarshal(contents, &envelope)
	if err != nil {
		return envelope, err
	}

	return envelope, nil
}

func decryptMasterKey(envelope masterKeyEnvelope, password string) ([]byte, error) {
	if envelope.KDF != cKDFName {
		return nil, fmt.Errorf("unsupported kdf %q", envelope.KDF)
	}
	if envelope.Cipher != cCipherName {
		return nil, fmt.Errorf("unsupported cipher %q", envelope.Cipher)
	}

	wrapKey := deriveWrapKey(password, envelope.Salt)
	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, envelope.Nonce, envelope.Ciphertext, nil)
}

func deriveWrapKey(password string, salt []byte) []byte {
	threads := uint8(cArgonThreads)
	if runtime.NumCPU() < cArgonThreads {
		threads = uint8(runtime.NumCPU())
	}
	if threads == 0 {
		threads = 1
	}

	return argon2.IDKey([]byte(password), salt, cArgonTime, cArgonMemory, threads, cWrapKeyLen)
}

func randomBytes(length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func promptNewPassword() (string, error) {
	password, err := readPassword(cPasswordPrompt)
	if err != nil {
		return "", err
	}

	confirmPassword, err := readPassword(cPasswordConfirm)
	if err != nil {
		return "", err
	}
	if password != confirmPassword {
		return "", errors.New("passwords do not match")
	}

	return password, nil
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stdout, prompt)
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stdout)
	if err != nil {
		return "", err
	}

	return string(passwordBytes), nil
}

func readPasswordFromStdin() (string, error) {
	passwordBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(passwordBytes)), nil
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

func newMasterKeyManager() (opkg.MasterKeyManager, error) {
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("resolve user config directory: %w", err)
	}

	return opkg.NewFilesystemMasterKeyManager(userConfigDir), nil
}

func newVaultService() (opkg.VaultService, error) {
	masterKeyManager, err := newMasterKeyManager()
	if err != nil {
		return opkg.VaultService{}, err
	}

	return opkg.NewVaultService(
		masterKeyManager,
		opkg.NewFilesystemIndexStore(),
		opkg.NewFilesystemObjectStore(),
	), nil
}

func writeTopLevelUsage(w io.Writer) {
	lines := []string{
		"Bulletproof secrets in the open.",
		"",
		"Usage:",
		fmt.Sprintf("  %s <command> [flags]", cToolName),
		"",
		"Commands:",
	}

	for _, cmd := range cCommands {
		lines = append(lines, fmt.Sprintf("  %-8s %s", cmd.name, cmd.summary))
	}

	lines = append(lines,
		"",
		"Examples:",
		fmt.Sprintf("  %s init", cToolName),
		fmt.Sprintf("  %s unlock", cToolName),
		fmt.Sprintf("  %s unlock secrets/prod.env", cToolName),
		fmt.Sprintf("  %s lock secrets/prod.env", cToolName),
		fmt.Sprintf("  %s lock", cToolName),
		"",
		fmt.Sprintf("Use %q for more details.", cToolName+" help <command>"),
	)

	writeLines(w, lines...)
}

func writeCommandUsage(w io.Writer, cmd command) {
	lines := []string{
		"Usage:",
		"  " + cmd.usageLine,
		"",
		cmd.description,
	}

	switch cmd.name {
	case "init":
		lines = append(lines,
			"",
			"Example:",
			fmt.Sprintf("  %s init", cToolName),
		)
	case "unlock":
		lines = append(lines,
			"",
			"Flags:",
			"  --password-stdin    Read the password from stdin when starting a session.",
			"",
			"Examples:",
			fmt.Sprintf("  %s unlock", cToolName),
			fmt.Sprintf("  %s unlock secrets/", cToolName),
			fmt.Sprintf("  %s unlock secrets/prod.env", cToolName),
		)
	case "lock":
		lines = append(lines,
			"",
			"Flags:",
			"  --keep              Keep plaintext files after locking paths.",
			"",
			"Examples:",
			fmt.Sprintf("  %s lock", cToolName),
			fmt.Sprintf("  %s lock secrets/", cToolName),
			fmt.Sprintf("  %s lock secrets/prod.env --keep", cToolName),
		)
	case "help":
		lines = append(lines,
			"",
			"Example:",
			fmt.Sprintf("  %s help unlock", cToolName),
		)
	}

	lines = append(lines,
		"",
		fmt.Sprintf("Folder metadata lives under %s/%s.", cStoreDir, cConfigFile),
	)

	writeLines(w, lines...)
}

func writeLines(w io.Writer, lines ...string) {
	fmt.Fprintln(w, strings.Join(lines, "\n"))
}
