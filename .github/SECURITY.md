# Security Policy

## Supported versions

| Version | Supported |
|:---|:---|
| The latest release tag and `main` | Best effort |
| Any earlier release | No. Fixes land on `main` and ship in the next release; there is no backporting |

This is DFIR tooling maintained as a personal project. It is built to read
evidence, not to be exposed to untrusted input over a network, and nothing in
it is hardened beyond what its README states.

## Reporting a vulnerability

Open a [private security advisory](https://github.com/Get-Sybers/gomount/security/advisories/new)
rather than a public issue. If advisories are unavailable, open an issue that
describes the *class* of problem without a working exploit, and say you have
details to share privately.

Expect a slow response: this is a personal project, not a maintained product.

## Handling evidence

The data this tool touches is usually sensitive and sometimes legally
significant.

- Work on copies, and verify hashes before and after processing.
- Treat every input as hostile: the parsers read on-disk structures from the
  evidence, and a crafted file can make them misbehave.
- Nothing here is written to preserve chain of custody on its own. If your
  work needs to stand up in a legal context, this tool is not sufficient alone.
