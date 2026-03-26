# Safe Filesystem Cache

## Problem

OpenSecrets currently writes the decrypted master key into machine-local session state on disk.

Current shape:

- folder metadata lives under `.opensecrets/`
- bare `unlock` decrypts the master key
- local session state is written outside the protected folder
- that session state currently contains `master_key`

Example of the current session file shape:

```json
{
  "folder_path": "/Users/hans/Documents/super_secret_docs",
  "created_at": "2026-03-26T23:45:34Z",
  "master_key": "..."
}
```

This is effectively the plaintext master key encoded for JSON transport.

That means the current implementation improves UX, but weakens the local security model because a user-level filesystem read can recover the decrypted key material directly.

## Why This Is Risky

Writing the decrypted master key to a normal JSON file means:

- the key is persisted beyond the interactive unlock moment
- the key is readable by anything that can read the session file
- the file becomes a high-value local target
- the cache format is stronger for convenience than for security

For a secret manager, this should be treated as a temporary implementation only.

## Findings

The current product findings are:

- storing the decrypted master key in plaintext-equivalent form on disk is not a good final design
- serious secret managers usually avoid this pattern
- better common patterns are:
  - keep decrypted key material in memory only
  - store secrets in the OS credential store
  - use a long-lived agent that keeps unlocked key material in memory
  - require re-authentication rather than persisting decrypted keys freely

For this project, the most practical next direction is to use OS keyring storage instead of a normal session JSON file for secret material.

## Cross-Platform Direction

The product needs to support:

- Linux
- macOS
- Windows

The current recommendation is to use an OS keyring abstraction and keep the filesystem session file as metadata-only state.

Recommended split:

- filesystem session file:
  - folder path
  - creation time
  - optional TTL or lock metadata
- OS keyring entry:
  - decrypted master key or equivalent session secret

## Candidate Approach

Use a stable key per protected folder:

- service: `opensecrets`
- account/key name: hash of folder path

Then:

1. `unlock` prompts for password
2. `unlock` decrypts the master key
3. decrypted key material is written to the OS keyring
4. local filesystem session state stores only metadata

This preserves multi-command usability without leaving the decrypted master key in a normal JSON file.

## Non-Goals For This Step

This roadmap item is not yet about:

- path-level lock/unlock behavior
- background daemons
- session expiration policy
- key sharing between users

Those may matter later, but they should not block removing plaintext-equivalent key material from the filesystem cache.

## Acceptance Criteria

This roadmap item is complete when:

- `unlock` no longer writes the decrypted master key into a normal JSON file
- filesystem session state contains metadata only
- decrypted key material is stored in a safer local mechanism
- the mechanism works on Linux, macOS, and Windows

## Notes

- the current on-disk session format is acceptable only as a temporary scaffold
- the codebase should keep a clear TODO near the current session write path until this is replaced
