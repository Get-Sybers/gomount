<!-- The title becomes the squash commit: `type(scope): summary` (Conventional Commits). -->

## What and why

<!-- What changes, and the reasoning that is not in the diff. -->

## Checklist

- [ ] `make conform` and `make lint` are green locally (the same gate CI runs)
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]` (Keep a Changelog)
- [ ] Tests cover the change: table-driven, standard `testing` package, goldens under `testdata/`
- [ ] No evidence, credentials or generated output is committed
- [ ] Documentation (`README.md`, package docs) matches the behaviour
