# Releasing

1. Ensure tests pass with `go test ./...`.
2. Ensure pre-commit hooks are green with `pre-commit run --all-files`.
3. Update versioned install examples in [README.md](./README.md) to the new tag. The README should always point at the latest released tag, for example `@v0.1.0`.
4. Create an annotated Git tag like `v0.1.0`.
5. Push the tag.
6. Publish a GitHub release with release notes.

This repository uses GitHub releases as the release history. A local changelog file is intentionally not maintained.
