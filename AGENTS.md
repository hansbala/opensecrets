# OpenSecrets Notes

This repository is currently documentation-first.

Primary docs:

- [API](./docs/API.md)
- [Architecture](./docs/ARCHITECTURE.md)
- [Go Rules](./docs/GO_RULES.md)
- [Feature: Filename Privacy](./docs/features/FILENAME_PRIVACY.md)

Current direction:

- OpenSecrets protects files inside an arbitrary folder, not just a Git repository
- each protected folder uses a fixed hidden metadata directory at `.opensecrets/`
- the CLI is intentionally small and session-based
- encrypted storage should use opaque object identifiers and an encrypted index

For implementation details, start with the docs above and treat them as the current source of truth.

Maintenance rules:

- keep documentation up to date as decisions change
- add new design notes under `docs/` using clear, focused filenames
- update this `AGENTS.md` index whenever docs are added, moved, renamed, or removed
- prefer changing the relevant doc in the same patch as the code or design change that requires it
