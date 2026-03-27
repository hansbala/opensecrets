# Directory Edge Cases

## Problem

OpenSecrets now supports recursive directory lock and unlock operations, but the current implementation is intentionally simple.

That means there are known edge cases and missing guarantees around directory behavior.

## Current Findings

### Empty directories are not preserved

Only files are indexed and stored.

If a directory tree contains an empty directory, locking and unlocking the tree will not recreate that empty directory.

### Directory metadata is not preserved

OpenSecrets recreates parent directories as needed during unlock, but it does not currently preserve:

- original directory permissions
- original directory timestamps
- other directory metadata

### Symlink behavior is not defined

The current recursive implementation is not designed around a formal symlink policy.

This should be made explicit before treating the implementation as hardened.

### Partial subtree conflicts can fail mid-operation

If a directory unlock encounters an existing plaintext file partway through the tree, some earlier files may already have been restored before the failure occurs.

### No transactional rollback

Directory lock and unlock currently operate file by file.

If one file fails, already-processed files are left in their current state.

### Locked-entry overwrite is path-based only

When relocking with `--force`, entries are replaced by path, without richer merge or divergence tracking.

### Orphaned encrypted objects are possible

If a file is relocked and gets a new object, the old encrypted object is not garbage-collected yet.

### Large directory trees may be slow

The current implementation is straightforward recursive traversal with no batching, progress display, or optimization for large trees.

## Why This Matters

Directory operations feel simple from the CLI, but users will expect them to be predictable and durable.

The current implementation is functional, but it is not yet a hardened lifecycle for large or messy directory trees.

## Recommended Next Steps

Priority order:

1. define failure semantics for partial directory operations
2. add orphaned object cleanup or at least orphan tracking
3. decide whether empty directories should be preserved
4. define and document symlink behavior explicitly
5. improve UX for large directory trees

## Acceptance Criteria

This area is in a better state when:

- directory failure behavior is explicitly documented
- partial failures do not leave surprising silent state
- object lifecycle is managed more cleanly
- empty-directory behavior is a deliberate product decision
- symlink handling is explicit and tested
