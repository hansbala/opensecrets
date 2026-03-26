# OpenSecrets Architecture

## Purpose

OpenSecrets protects files inside an arbitrary folder, not just a Git repository.

The core model is:

- a protected workspace
- an encrypted backing store
- a local authenticated session

If the workspace is later committed to Git, only the encrypted metadata and encrypted file contents should be tracked.

## Workspace Layout

Each protected workspace contains a hidden metadata directory:

```text
<workspace>/
  .opensecrets/
    config.toml
    masterkey.enc
    store/
```

Notes:

- `.opensecrets/` is hidden by default to reduce clutter
- the storage path should be configurable, but `.opensecrets/` is the default
- the workspace config file lives at `.opensecrets/config.toml`

## Local State

Passwords are not stored.

OpenSecrets should keep workspace-portable data inside the workspace and machine-local session state outside the workspace.

Recommended split:

- workspace config and encrypted store: inside `.opensecrets/`
- local session state: OS-specific user application data directory

Examples:

- macOS: `~/Library/Application Support/opensecrets/`
- Linux: `~/.local/share/opensecrets/`

Local session state should contain only session data, such as:

- repo or workspace identifier
- unlocked path metadata
- session expiry information
- optional lock/PID metadata

The decrypted master key should ideally remain in memory only. If session persistence across commands is needed, store only local session material, not the password.

## Encryption Model

The recommended v0 crypto design is:

- `Argon2id` for password-based key derivation
- `XChaCha20-Poly1305` for authenticated encryption
- a random 256-bit master key generated at `init`

Flow:

1. The user enters a password.
2. `Argon2id` derives a key from the password and a salt.
3. The derived key encrypts the master key.
4. The master key encrypts file contents.

This keeps the UX simple while avoiding direct file encryption with the raw password.

## Performance Model

Password-based unlock should be the expensive step.

- `unlock` may take noticeable time because `Argon2id` is intentionally costly
- file encryption and decryption should be fast once the session is open
- path-based operations should scale mostly with file size and file count

This is why the CLI separates session authentication from path operations.

## CLI Model

The CLI is intentionally small:

```bash
opensecrets init
opensecrets unlock
opensecrets unlock <path>...
opensecrets lock <path>...
opensecrets lock
```

Semantics:

- `init` initializes the workspace and prompts for a new password
- `unlock` authenticates and starts a local session
- `unlock <path>` decrypts files or directories into the workspace
- `lock <path>` encrypts files or directories back into the backing store and removes plaintext by default
- `lock` with no path locks all tracked unlocked paths and clears the local session

## Safety Rules

The tool must not silently overwrite user data.

Required behavior:

- `unlock <path>` refuses to overwrite existing plaintext unless `--force` is used
- `lock <path>` refuses to overwrite newer encrypted state unless `--force` is used
- bare `lock` only operates on paths known to be currently unlocked

To support this, local state should record for each unlocked path:

- plaintext path
- encrypted object or version identifier
- plaintext digest at unlock time
- current unlocked status

## Language Choice

Go is the recommended implementation language for v0.

Reasons:

- easy single-binary distribution
- good cross-platform support
- strong standard library for filesystem and CLI work
- solid crypto support
- fast enough for the workload

A single-file prototype in `main.go` is reasonable for the first version if the scope remains tight.

## External Dependencies

The implementation should stay light.

Recommended dependencies:

- `golang.org/x/crypto`
  For `argon2` and `chacha20poly1305`
- `golang.org/x/term`
  For password prompts without terminal echo
- a TOML library such as `github.com/pelletier/go-toml/v2`
  For workspace config parsing and writing

The standard library should handle most of the remaining work.
