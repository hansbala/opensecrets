# Filename Privacy

## Goal

OpenSecrets should support hiding file and directory names from the encrypted backing store.

This matters for users who want the workspace to reveal as little as possible when it is copied, synced, or committed.

## Design

The encrypted store should use opaque object identifiers rather than plaintext paths.

Recommended layout:

```text
<workspace>/
  .opensecrets/
    config.toml
    masterkey.enc
    index.enc
    store/
      7f/
        7f8c2d...
      a1/
        a19b44...
```

Notes:

- file contents are stored as encrypted blobs
- blob names are opaque object identifiers
- original file and directory names are not stored in plaintext in the backing store

## Encrypted Index

Path metadata should live in an encrypted index file such as `.opensecrets/index.enc`.

The decrypted index maps logical workspace paths to encrypted objects.

Example logical mappings:

- `secrets/prod.env` -> object `7f8c2d...`
- `certs/api/key.pem` -> object `a19b44...`

The index may also store:

- file size metadata
- timestamps if needed
- content digests
- version identifiers for conflict detection

Because the index is encrypted, path names remain hidden until the user authenticates and opens a session.

## CLI Implications

This design works well with the current CLI:

```bash
opensecrets init
opensecrets unlock
opensecrets unlock <path>...
opensecrets lock <path>...
opensecrets lock
```

Important behavior:

- bare `unlock` becomes the step that authenticates and makes the encrypted index available
- `unlock <path>` resolves the requested logical path through the decrypted index
- `lock <path>` updates both the encrypted blob store and the encrypted index

## Residual Metadata Leakage

Hiding filenames does not hide everything.

The backing store may still reveal:

- number of encrypted objects
- approximate file sizes
- update timing

Padding could reduce file-size leakage, but it should not be required for v0.

## Recommendation

The encrypted store should always use opaque object names and an encrypted index.

This keeps the storage format simple and avoids maintaining one mode that hides filenames and another that does not.
