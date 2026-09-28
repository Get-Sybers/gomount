# Conformance status

Where the monorepo stands against `docs/go-standards.md` and `docs/ansible-standards.md`, and what
remains. Run the gates yourself:

```
make conform      # go-conform + ansible-conform
make upgrade      # raise everything to the highest allowed versions, then re-conform
```

This checkout is a **curated collection** of the ecosystem's Go and Ansible material. Some glue
that lives in the full product repos is not here (the pipeline-image build contexts for anamnesis,
byakugan and plaso; Byakugan's `model/`; the `data_store/` runtime tree). Those gaps are noted
below; they are resolved in the full ecosystem, not in this library.

## What is verified here

- **Monorepo layout.** One repository: lowercase component dirs (`anamnesis`, `byakugan`,
  `dx-dfir`, `godfir-toolz`); the Ansible collections in the native
  `ansible_collections/get_sybers/{dxdfir,godfir_toolz}/` tree; a root `ansible.cfg` resolving both
  collections in-repo.
- **Go: `go-conform` passes — 29 checks green.** Every module builds, vets, and tests; `gofmt`
  clean; module paths all `github.com/get-sybers/dev-library/...`; no exported `Get*` accessors;
  the one repo toolchain (`go 1.26.0`, the floor `gomemprocfs` and `golang.org/x/sys` force); the
  root `go.work` over all modules; the intra-repo dependencies wired by relative `replace`.
- **De-duplication.** The shared tool core lives once in `pinfo/{toolkit,framework,diskimage,tstamp}`
  and is imported by every tool that needs it; ~1.5k lines of copied runtime/summary/image/timestamp
  code removed, and the last byte-identical primitives (`Prefix`, `ParseBool`, the writable-dir probe,
  the item-name fold) now live once in `pinfo/toolkit` (see §1 below).
- **`go:generate`.** Byakugan's `ir.json` regenerates byte-identically via `go generate ./...`;
  `go-conform`'s drift check guards it.
- **Ansible structure + lint.** `ansible-conform` passes 33/33 — the collection and role
  must-haves, `dir == name`, the exact-pin check, and `ansible-lint --profile production` on both
  the `dxdfir` and `godfir_toolz` collections (run here with the installed tool, offline against
  each collection's own `.ansible-lint`).
- **The two scripted mechanisms** (`scripts/{go,ansible}-{conform,upgrade}.sh`) and the root
  `Makefile` that fans out across modules and collections.

## Staged for CI (cannot be proven in this environment)

| Item | Why | Gate that runs it |
|---|---|---|
| `goyara` build/test | needs CGO + `libyara` (absent here) | `go-conform` builds it where libyara is present |
| `molecule test` per role | needs `community.docker`; Ansible Galaxy is blocked by org policy (403) here | `ansible-conform` / CI |
| `contract.yml` schema validation | `jsonschema`/`PyYAML` not installed | `ansible-conform` runs it when present |
| `cve-scan.sh` (SBOM + CVE gate) | needs `syft`/`grype`; producer-side only | release gate |
| dxdfir/ansible runtime behaviour | needs docker images + ansible | CI / a provisioned host |

## Partial-collection gaps (resolved in the full ecosystem)

- Pipeline-image build contexts `godfir-toolz/{anamnesis,byakugan,plaso}/` (Dockerfile + contract)
  are not carried here, so the lane roles that reference those contracts (`dxdfir_anamnesis`,
  `dxdfir_byakugan`, `dxdfir_plaso`) cannot be contract-fit-checked here — `repogate`'s
  `TestReferencedContractsExistAtThePin` is skipped, and the byakugan engine-pin test is skipped.
- `data_store/` (engine runtime output, deny-by-default `.gitignore`) is not carried; the
  `repogate` engine-output tests are skipped.

## Remaining conformance work

### 1. Shared Go core — de-duplication

The standard forbids duplication (go-standards.md §7). The shared core now lives in the `pinfo`
library module and is imported, not copied:

- **`pinfo/toolkit`** — the behaviour-identical primitives both batch runtimes shared verbatim: the
  `Prefix` env-name derivation, the framework `ParseBool` spellings, the writable-dir probe, and the
  item-path → output-folder `FoldName`. `framework` and `batch` re-export `Prefix`/`ParseBool` so
  their bound tools are untouched.
- **`pinfo/framework`** — the container batch runtime (env contract, discovery loop, record files,
  idempotency, one summary line, exit codes), with the item-name fold set as a `Tool.FoldExts`
  field. Consolidated from the byte-identical copies in `gowindowlicker/batch`,
  `signatures/batch.go` and `zeek/batch.go` (~1370 lines removed); all three now import it.
- **`pinfo/framework.Summary`/`Failure`** — the run summary contract; `gomount` uses it in place of
  its own copy.
- **`pinfo/diskimage`** — disk-image discovery/selection/naming/materialise, shared by
  `gowindowlicker` and `godaemonhunter` (which keeps only its Mac two-pass extension).
- **`pinfo/tstamp.RFC3339Nano`** — the Windows record timestamp, replacing the identical `ts()`
  copies in the `mft`, `appcompat` and `le` parsers.

**Still outstanding — one deeper unification, deliberately deferred.** `godaemonhunter` drives its
parsers through `pinfo/batch`, a *second* runtime whose `Process` takes the stamping
`*record.Writer` (CAR provenance) rather than `pinfo/framework`'s `io.Writer`. The two runtimes
share ~80% of their loop/config/summary logic but differ in that writer contract. Collapsing them
into one (a writer interface both satisfy, or a generic `Tool[W]`) would touch all 15 godaemonhunter
sub-tools' `Process` signatures and the provenance stamping — behaviour, not packaging — so it is
left as a focused follow-up rather than risked here. The multi-tool orchestration helpers that read
as duplicated across `godaemonhunter` and `gowindowlicker` (`configErrorSummary`, `runSubOnImage`)
are the *same shape over the two divergent `Summary`/runtime types*, not byte-identical code, so they
fold only once that runtime merge lands — not before. The per-image aggregate summaries
(`huntSummary`, `lickSummary`) are genuine tool-specific roll-ups, not copies.

### 2. Other Go details

- Resolve the cross-module name collisions before any shared package is lifted: `fsx`, `identify`,
  `timeline` each mean different things in different modules (go-standards.md §7).
- Retire `testify` from the dx-dfir front-end in favour of stdlib assertions (go-standards.md §11).
- Fixture generation: normalise the Python/Go/shell generators onto `go:generate` (§5, §11).

### 3. Ansible

- Molecule scenarios for the infra/deploy roles (`dxdfir_byakugan`, `dxdfir_car_load`,
  `dxdfir_cleanup`, `dxdfir_export`, `dxdfir_stack`) — added, verified by CI.
- Declare the role→role couplings in `meta/main.yml` `dependencies:` (the lane and build-galaxy
  delegations), rather than relying on `roles_path` (ansible-standards.md §3).
- Migrate the `contract.yml` schema check from `conform.sh` into a molecule/collection test
  (`ansible.utils.validate`); retire `conform.sh --build` in favour of the `godfir_build` role's
  own verification (ansible-standards.md §10, §13).

### 4. Licensing (needs a decision)

Component licenses differ — `anamnesis`/`byakugan` are MIT, `dx-dfir`/`godfir-toolz` are Apache-2.0
— and the `dxdfir` collection historically declared MIT while its repo `LICENSE` is Apache-2.0. A
monorepo wants one root `LICENSE`; picking it (and aligning every `galaxy.yml` `license` to it) is a
licensing decision, left for the owner rather than chosen here.
