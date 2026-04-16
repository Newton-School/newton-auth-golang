# Releasing

1. Ensure tests pass with `go test ./...`.
2. Ensure pre-commit hooks are green with `pre-commit run --all-files`.
3. Update any versioned install examples in [README.md](./README.md) if needed.
4. Create an annotated Git tag like `v0.1.0`.
5. Push the tag.
6. Publish a GitHub release with release notes.

This repository uses GitHub releases as the release history. A local changelog file is intentionally not maintained.
