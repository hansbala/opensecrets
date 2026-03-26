package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	cToolName    = "opensecrets"
	cStoreDir    = ".opensecrets"
	cConfigFile  = "config.toml"
	cExitUsage   = 2
	cExitFailure = 1
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
	storePath := fs.String("store-dir", cStoreDir, "Metadata directory created in the folder root.")

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

	return notImplemented(
		"init",
		fmt.Sprintf("folder=%s store-dir=%s", cwd, *storePath),
		"will initialize the folder metadata and prompt for a password",
	)
}

func runUnlock(args []string) error {
	cmd, _ := findCommand("unlock")
	fs := newFlagSet(cmd)
	force := fs.Bool("force", false, "Overwrite conflicting plaintext when unlocking paths.")
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

	mode := "session"
	if len(paths) > 0 {
		mode = "paths"
	}

	return notImplemented(
		"unlock",
		fmt.Sprintf("mode=%s force=%t password-stdin=%t paths=%s", mode, *force, *passwordStdin, formatPaths(paths)),
		"will start a session or unlock the requested files and directories",
	)
}

func runLock(args []string) error {
	cmd, _ := findCommand("lock")
	fs := newFlagSet(cmd)
	force := fs.Bool("force", false, "Override divergence checks when locking paths.")
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

	mode := "session"
	if len(paths) > 0 {
		mode = "paths"
	}

	return notImplemented(
		"lock",
		fmt.Sprintf("mode=%s force=%t keep=%t paths=%s", mode, *force, *keep, formatPaths(paths)),
		"will lock the requested files or close the active session",
	)
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
			"Flags:",
			fmt.Sprintf("  --store-dir string   Metadata directory created in the folder root. (default %q)", cStoreDir),
			"",
			"Example:",
			fmt.Sprintf("  %s init", cToolName),
		)
	case "unlock":
		lines = append(lines,
			"",
			"Flags:",
			"  --force             Overwrite conflicting plaintext when unlocking paths.",
			"  --password-stdin    Read the password from stdin when starting a session.",
			"",
			"Examples:",
			fmt.Sprintf("  %s unlock", cToolName),
			fmt.Sprintf("  %s unlock secrets/", cToolName),
			fmt.Sprintf("  %s unlock secrets/prod.env --force", cToolName),
		)
	case "lock":
		lines = append(lines,
			"",
			"Flags:",
			"  --force             Override divergence checks when locking paths.",
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
