# Go Rules

## Purpose

These rules are for the initial OpenSecrets Go implementation.

The goal is to keep the code small, explicit, and easy to refactor as the design settles.

## General Style

- follow standard Go formatting with `gofmt`
- prefer the standard library unless an external dependency clearly earns its place
- keep names short, direct, and domain-specific
- prefix all constants with `c`
- prefix variables that are intentionally used as constants with `c`
- write explicit type annotations for each variable or parameter name instead of sharing one trailing type across multiple names
- avoid clever abstractions in v0
- write code that is easy to trace from CLI entrypoint to filesystem and crypto operations

## Project Structure

- keep the implementation in a single `main.go` file for the initial version
- split files only when the current file becomes hard to navigate
- keep package structure shallow until there is real pressure to separate concerns

## Error Handling

- return errors instead of hiding them
- include enough context in error messages to identify the failed path or operation
- do not panic for expected user or filesystem errors
- fail closed for security-sensitive operations

## CLI Behavior

- keep command behavior predictable and explicit
- refuse destructive overwrites by default
- require `--force` for conflict overrides
- keep help text short and concrete

## Filesystem Rules

- prefer atomic writes for config, metadata, and encrypted index updates
- preserve permissions intentionally rather than accidentally
- clean up partial output on failure where practical
- never silently delete user plaintext unless that is the documented behavior of the command

## Crypto Rules

- use vetted primitives only
- do not invent custom cryptography
- keep crypto choices centralized and easy to audit
- separate password-derived key handling from file-content encryption
- authenticate encrypted metadata, not just file blobs

## Config Rules

- use TOML for user-edited config
- keep machine-generated state out of user-edited config files
- keep folder-portable config inside `.opensecrets/`
- keep machine-local session state outside the folder

## Testing Rules

- use `testify/require` for assertions in tests
- test path conflict behavior early
- test partial failure cases around writes and interruptions
- test lock/unlock behavior on both files and directories
- test that plaintext is not overwritten silently
- test that encrypted metadata can round-trip across sessions

## Dependencies

- keep dependencies minimal
- ask the user before adding new dependencies
- prefer `golang.org/x/crypto` and `golang.org/x/term` for the known needs
- add a TOML library only for config parsing and writing
- avoid large CLI frameworks unless the command surface actually grows

## Code Review Bias

When reviewing Go changes in this repository, prefer:

- simpler control flow over abstraction
- explicit path and state handling over hidden magic
- small, auditable crypto boundaries
- narrow interfaces only when they remove real coupling
