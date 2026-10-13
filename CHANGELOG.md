# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- The conformance gate of the get-sybers standard (DX_DFIR
  `docs/reference/build-and-test.md`): `make conform` (gofmt, vet, build,
  shuffled tests with coverage, `go mod tidy -diff`, a `go:generate` drift
  check and `scripts/structlint.sh`), `make lint` (golangci-lint v2,
  `.golangci.yml`) and `make vuln` (govulncheck), run by the `CI` workflow on
  every push and pull request — on amd64 and arm64 — with `all_green` as the
  one required status check.
- Repository hygiene: `.editorconfig`, `.gitattributes`, `.shellcheckrc`,
  Dependabot (actions and Go modules, weekly, grouped), `CODEOWNERS`, a
  security policy and a pull-request template.

### Changed
- The findings the new lint gate surfaced, none of which changes behaviour:
  `errors.Is` for the `io.EOF` comparisons and `errors.As` for the
  `*WalkErrors` assertion; deferred and error-path closers explicitly
  discarded; local names that shadowed the `min` and `max` builtins renamed;
  the HFS+ volume-label lookup flattened out of its `else`; the filesystem
  registries pass their `probe`/`Open` functions directly instead of through
  wrapping closures; test fixtures built with `slices.Concat`.

### Removed
- Dead code the gate's `unused` check found: the HFS+ `xattr.size`,
  `xattr.readerAt`, `bytesReaderAt`, `btree.first` and `FS.readAt` helpers,
  the `treeNode` type of the HFS+ test builder, the unused VHDX `head`
  signature and `vhdxParentBasename`.

## [0.2.1] - 2026-10-03

The last release before this changelog was started; see the git history for
this and the earlier tags.

## [0.2.0] - 2026-10-03

## [0.1.0] - 2026-09-28

[Unreleased]: https://github.com/Get-Sybers/gomount/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/Get-Sybers/gomount/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Get-Sybers/gomount/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Get-Sybers/gomount/releases/tag/v0.1.0
