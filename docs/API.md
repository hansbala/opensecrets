# OpenSecrets CLI API

## Overview

The CLI is intentionally small:

```bash
opensecrets init
opensecrets unlock
opensecrets unlock <path>...
opensecrets lock <path>...
opensecrets lock
```

This gives the user two concepts:

- a local authenticated session
- path-based locking and unlocking for files or directories

`<path>` may refer to either a file or a directory. Directory operations recurse.

## Commands

### `opensecrets init`

Initializes OpenSecrets in the current repository.

Responsibilities:

- create repo metadata under `.opensecrets/`
- prompt the user for a password
- derive a wrapping key from that password
- generate and store an encrypted master key
- write repo config

Expected result:

- the repo is ready to encrypt and decrypt tracked paths

### `opensecrets unlock`

Prompts for the password and starts a local authenticated session.

Responsibilities:

- derive the key-encryption key from the password
- decrypt the repo master key
- keep the master key in local session state

Expected result:

- subsequent `unlock <path>` and `lock <path>` commands can run without prompting again

### `opensecrets unlock <path>...`

Decrypts one or more files or directories into the working tree.

Responsibilities:

- require an active local session, prompting first if needed
- restore plaintext for each requested path
- record local state for conflict detection

Default safety rules:

- do not overwrite an existing plaintext file silently
- fail if plaintext already exists and differs from the encrypted source
- require `--force` to overwrite

### `opensecrets lock <path>...`

Encrypts one or more files or directories back into the encrypted store.

Responsibilities:

- read plaintext from the requested paths
- write encrypted content into the repo-backed store
- update metadata as needed
- remove plaintext by default after successful encryption

Default safety rules:

- do not overwrite encrypted state silently if it changed since the path was unlocked
- fail on divergence unless `--force` is passed

### `opensecrets lock`

Ends the current authenticated session and "goes dark."

Responsibilities:

- lock all currently tracked unlocked paths
- remove decrypted plaintext for those paths
- clear local session state
- forget the in-memory master key

Expected result:

- no local unlocked session remains
- previously unlocked plaintext managed by OpenSecrets is removed

## Safety Model

The CLI must not silently destroy user data.

Rules:

- `unlock <path>` never silently overwrites existing plaintext
- `lock <path>` never silently overwrites newer encrypted state
- `--force` is required when the user wants to override either safeguard

## Local State

OpenSecrets needs small local state to support conflict detection and bare `lock`.

For each unlocked path, local state should record:

- plaintext path
- encrypted object/version identifier
- plaintext digest at unlock time
- whether the path is currently considered unlocked

This state is local machine state and is cleared by bare `lock`.

## Notes

- `lock` is both a path operation and the session-closing command
- `unlock` without a path is authentication only
- `unlock <path>` is the restore operation
- no separate `close`, `clean`, or `go-dark` command is needed in this model
