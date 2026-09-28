# Ansible standards

These rules govern every collection, role, and playbook in the ecosystem, which lives in one
repository — a monorepo — alongside the Go modules. Collections use the native layout within it and
resolve in-repo.

One sentence governs the rest: **a role performs actions and a playbook decides which run; every
value arrives through the native variable system; every task is idempotent and honest about
change.**

## 1. Placement, namespace, and naming

The galaxy namespace is `get_sybers` (underscore — the one place the organisation cannot take a
hyphen). Every collection lives in the native layout under one tree in the repository, and resolves
from there:

```
<repo>/ansible_collections/get_sybers/<name>/
```

`collections_path` and `roles_path` point at this in-repo tree, so a collection and a role in
another collection resolve directly — no git submodule and no galaxy-install fallback. The
directory `<name>`, the `name` declared in `galaxy.yml`, and the prefix every role is named with all
agree: one fully-qualified name, no second spelling.

## 2. Collection must-haves

| File | Rule |
|---|---|
| `galaxy.yml` | each dependency bounded `>=x.y.z,<next-major`; `license` matches the repo `LICENSE` |
| `meta/runtime.yml` | one `requires_ansible` floor, agreeing with every role's `min_ansible_version` |
| `requirements.yml` | the single source of pinned versions — every dependency an exact `X.Y.Z`, never a range, `:latest`, or a branch |
| `README.md` · `CHANGELOG.md` | how it is consumed; Keep a Changelog |
| `.ansible-lint` | `profile: production` |

Every pinned version lives in `requirements.yml` and nowhere else; scripts and bootstrappers read
it rather than carrying their own copy. `molecule/` is `build_ignore`d from the artifact.

## 3. Role must-haves

Every role, without exception, ships: `meta/main.yml` (with `galaxy_info` and an explicit
`dependencies:` list), `meta/argument_specs.yml` (every input typed and described),
`defaults/main.yml` (a self-contained default for each input), `tasks/` (split by stage),
`molecule/default/` (a scenario with a committed real fixture, plus `converge`/`verify`/`prepare`),
and a `README.md`. A role resolves and tests in isolation from its own metadata — a dependency on
another role, in the same collection or another, is **declared**, never left for `roles_path` to
satisfy.

## 4. Variables — the native system only

Every variable enters through native precedence and nothing else:

- **`defaults/main.yml`** — overridable inputs, each mirrored in `argument_specs.yml`.
- **`vars/main.yml`** — true constants only.
- **`group_vars/`** — shared identities, defined once and referenced by the roles that need them.
- **`host_vars/`** — per-host values.
- **`-e` / vault** — run-time overrides, which win over all of the above.

Two prohibitions make this concrete:

- **No inline `vars:`** on a play, a role invocation, or a task.
- **`set_fact` is only for values genuinely computed from runtime facts** — never to declare,
  default, or assemble configuration the precedence layers should own.

Static reference data is a declaration in these layers, or a data file loaded with `vars_files` /
`include_vars` / a `lookup` — never assembled inside a task.

## 5. The role acts; the playbook decides

A task performs one action and carries no branching logic. Which actions run is decided in the
playbook — a thin, single-purpose wrapper. Orchestration stays out of roles; actions stay out of
playbooks.

## 6. Don't repeat roles

A task sequence needed by more than one role is factored into one role the others delegate to and
declare as a dependency; in the monorepo that shared role resolves in-repo even across collections.
Copying tasks between roles is a defect. Parameterise the shared role; do not fork it.

## 7. Idempotence and honest change

Every task is idempotent: re-running a play changes nothing when nothing needs changing. Prefer a
module's own idempotence; otherwise gate with `creates`/`removes` or a `changed_when`/`failed_when`
tied to a real result. A blanket `changed_when: false` used to hide noise is not allowed. Molecule
proves this — a second `converge` reports zero changed.

## 8. Native modules over shell

Use a module wherever one exists (`ansible.builtin.*` and the collection's declared dependencies).
`command:`/`shell:` is a last resort — a liveness probe, or an operation with no module — always in
argv form, with `changed_when` set and a lint waiver naming the reason. Where a raw invocation is
unavoidable it is confined and identical everywhere it appears, never scattered ad hoc.

## 9. Inventory and secrets

The controlled host set is static inventory; what varies is discovered at run time, not hard-coded.
Secrets are generated once and read back thereafter, overridable, and never committed: a gitignored
per-host store, every secret-bearing task `no_log`, and the store excluded from inventory parsing.

## 10. Validate inputs and contracts natively

Assert a role's required inputs at its entry with a clear `fail_msg`. Validate external or
structured data against a schema with a native module (`ansible.utils.validate`), not a shelled-out
script. Bad input is a clean diagnostic, never a crash midway through a run.

## 11. Task conventions

- One naming form everywhere: `<role>-<stage> | lowercase description`, entry files and shared
  roles included.
- `block`/`rescue` around a fallible sequence surfaces one diagnostic; `block`/`always` cleans up on
  every exit path.
- `no_log` on anything secret-bearing.

## 12. Testing and assertions

Every role has a molecule scenario whose `verify.yml` asserts with `ansible.builtin.assert`, each
assertion an explicit `that:` with a `fail_msg`. Every scenario asserts idempotence (a second
`converge` reports zero changed), that the expected outputs exist, and that any produced summary or
interface carries its required keys. Every role has a negative scenario — a missing input or a
failing step resolves to a controlled skip or a clean error, never an uncaught crash. Fixtures are
committed and real.

## 13. The two scripted mechanisms

Both run at the repository root across every collection.

**`conform` — the gate.** One command, exit non-zero on any failure, run by CI and locally:
`ansible-lint --profile production`, `molecule test` for every scenario, schema validation of any
data contracts, the structure/naming/must-have checks of §1–§3 and §11, and the pin check (every
`galaxy.yml` dependency has an exact `requirements.yml` pin, and no version literal lives outside
it).

**`upgrade` — raise to the ceiling.** One command that raises every collection pin to the highest
release within its `galaxy.yml` bound and `ansible-core` to the highest within `requires_ansible`,
then runs `conform`; changes land only if `conform` passes. Those bounds are the only thing that
holds a version back.

## 14. Repository hygiene

The repository's single `LICENSE` governs; each collection's `galaxy.yml` `license` matches it. Each
collection carries its own `README.md`, `CHANGELOG.md`, `galaxy.yml`, `meta/runtime.yml`, and
`.ansible-lint`.

## 15. Enforcement

`conform` runs in CI over every collection on every change; nothing merges red. A rule `conform`
cannot yet check is a gap to close, not an exemption.
