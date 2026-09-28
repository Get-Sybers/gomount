# Go standards

These rules govern all Go in the ecosystem, which lives in one repository — a monorepo. The
repository holds **several Go modules, not one**, so that heavy or CGO dependencies stay isolated to
the modules that need them; a single workspace ties them together. A module either produces
commands or is an importable library, and the rules below apply to both.

One sentence governs the rest: **types and behaviour live in code, every static declaration lives
as data, and anything used in more than one place has one home and is imported.**

## 1. Repository shape and module paths

The repository is a monorepo of modules. Each module has its own `go.mod`, so its dependency set
and its `go` directive are its own and a CGO or heavy dependency never spreads beyond the module
that needs it.

```
<repo>/                         this repository — github.com/get-sybers/<repo>
  go.work                       lists every module below
  <module>/                     a Go module — own go.mod, path github.com/get-sybers/<repo>/<module>
    go.mod  cmd/  internal/
  <shared>/                     the module that holds code more than one module imports
  ansible_collections/          the Ansible side (see the Ansible standard)
  docs/  Makefile  README.md  CHANGELOG.md  LICENSE  .gitignore
```

- The organisation is `get-sybers` — lowercase, hyphen.
- Every module path is `github.com/get-sybers/<repo>/<module>[/<subpath>]`: lowercase, one path per
  module, no capitalised segments.
- A module imports another by that full path; the workspace (§2) resolves it in-repo.

## 2. The workspace, and how in-repo modules resolve

A single committed `go.work` at the repository root lists every module; it is the default way the
repository is built, edited, and tooled. A module that imports another in-repo module also wires it
with a **relative `replace`** to that module's path in the tree, so the module builds standalone —
`GOWORK=off go build ./... && go test ./...` passes in the module directory — and does not depend on
the workspace to compile. (The bare `require` of an unpublished in-repo module resolves to nothing
without this, because the module path maps to the real repository and Go looks for a published tag.)
A `replace` names only an in-repo module or a pinned third-party fork, each with a one-line reason.

## 3. Layout within a module

- **Commands are thin.** A command is one `cmd/<name>/main.go` (or a single root `main.go` for a
  one-command module) that wires the command together and maps exit codes — nothing else.
- **Logic is packaged by concern.** Implementation lives in `internal/<pkg>/`, one concern per
  package, each named for that concern and small enough to hold in one thought; dependencies
  between packages form no cycles.
- **The public surface is deliberate.** A package leaves `internal/` only when another module must
  import it; once public it is documented and kept stable. Everything else stays internal.

## 4. Go version and dependencies

The repository targets one Go toolchain version; a module's `go` directive is that version unless a
dependency forces a higher floor, which it then declares. A dependency shared by more than one
module resolves to one version across the repository. `go mod tidy` is clean in every module.
Versions move only through the upgrade mechanism (§12).

## 5. Static declarations are data, not code

Reference data — tables, mappings, enumerations, schemas, inventories, fixtures — is authored as a
declarative file and decoded into a typed value at load. A **type** is code; a **value that is
reference data** is data, and it never appears as a large literal in a `.go` source file.

- Use JSON for anything generated or shared across tools or languages (standard library, no
  dependency); use YAML for human-authored tables in a module that already decodes YAML.
- Data read by more than one toolchain lives at one canonical path and is loaded at runtime; data
  read only by Go is embedded with `go:embed`. Either way it is validated against a schema at load.
- When a table must exist at compile time, generate it from the data file with `go:generate`,
  commit and embed the artifact, and gate its freshness with a drift check (§11). The data file is
  the source of truth; the artifact is reproducible from it.

Code still binds names to behaviour — a registry that maps a name to a function is code, because a
function cannot be serialised — but its **data** (the names, the order) comes from the declaration.

## 6. Naming

Exported identifiers read as a phrase at the call site and never stutter their package
(`store.Check`, never `store.GetStoreStatus`). There are no `Get*` accessors; a name states the
verb of the work:

| Verb | Means |
|---|---|
| `Read` | read the contents of a file or stream |
| `Load` | load a module, library, table, or rule |
| `Check` | check a state or status |
| `List` | return a plural collection |
| `Run` | execute a command or job |
| `Classify` / `Detect` / `Is…` | classify by content |

Unexported helpers follow the same verbs. A package that mirrors a foreign API purely for
interoperability may keep that API's names where fidelity requires it; that is the only exception.

## 7. No duplication

Code used by more than one module lives in one shared module and is imported by its path. In a
monorepo this is frictionless, so copying shared code between modules is a defect, not a shortcut.
Behaviour that differs between callers is a parameter of the shared type, not a reason to fork it.
Shared reference data has one owning module and is imported or loaded from one path — never vendored
as a second copy.

## 8. Interfaces and the standard library

- Parse arguments with the standard library; add a CLI framework only where a rich multi-command
  operator experience earns it.
- Encode and decode with `encoding/json` and the standard codecs. Nothing hand-rolls what the
  standard library already provides.
- Accept interfaces, return concrete types; keep interfaces small and defined where they are
  consumed.

## 9. Native and optional dependencies

Reach an optional native dependency through a build tag with a `dlopen`/`purego` backend so the
default build stays `CGO_ENABLED=0`, and ship a stub that compiles and fails clearly when the
backend is absent. A dependency that genuinely requires CGO lives in its own module — this is why
the repository is multi-module — so it never forces cgo onto the rest.

## 10. Errors

Wrap with `%w`; let callers branch on sentinel or typed errors through `errors.Is`/`errors.As`. A
recoverable condition is a sentinel a caller can decline on, not a log line.

## 11. Testing and assertions

- The standard library `testing` only — **no third-party assertion library**. Assertions are
  explicit `got`/`want` comparisons with `t.Errorf`/`t.Fatalf`.
- Tests are **table-driven**, one `t.Run` subtest per case, named by case.
- Expected output is a **golden file** under `testdata/`, compared byte-for-byte and regenerated by
  a `-update` flag. Committed goldens are the spec.
- Tests are deterministic: a fixed clock and a fixed seed, never wall-clock or network.
- Every exported package has tests. Where a registry exists, a test asserts that registration and
  coverage agree. Integration tests drive the built artifact through `os/exec` behind a build tag,
  never a shell script. Fixtures are generated through `go:generate`.

## 12. The two scripted mechanisms

Both run at the repository root across every module, and per-module for a single module.

**`conform` — the gate.** One command, exit non-zero on any failure, run by CI and locally:
`gofmt -l`, `go vet ./...`, `go build ./...`, `go test ./...`, `go generate ./...` plus a drift
check, and a structural lint (module path, layout, no copied shared code, no `Get*`, no
reference-data literal that belongs in a data file, one version per shared dependency).

**`upgrade` — raise to the ceiling.** One command that moves each module's `go` directive and every
dependency to the highest version its hard limits allow (the resolved maximum, not a blind `-u`),
runs `go mod tidy`, then runs `conform`; changes land only if `conform` passes. The hard limits — a
dependency's floor, a security minimum, an API ceiling — are declared in one place and are the only
thing that holds a version back.

## 13. Repository hygiene

The repository carries one `LICENSE` (a single SPDX identifier, consistent wherever it is
declared), a root `.gitignore`, a root `README.md`, a `CHANGELOG.md` (Keep a Changelog), one
`go.work`, and one root `Makefile` whose targets fan out across the modules:
`build test vet fmt fmt-check tidy generate conform upgrade`. `fmt` writes; `fmt-check` gates. Each
module carries its own `go.mod` and a `README.md` for anything module-specific.

## 14. Enforcement

`conform` runs in CI over the whole repository on every change; nothing merges red. A rule
`conform` cannot yet check is a gap to close in the script, not an exemption.
