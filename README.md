# repo-public-check

[![CI](https://github.com/kantaro4123/repo-public-check/actions/workflows/ci.yml/badge.svg)](https://github.com/kantaro4123/repo-public-check/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Check a private Git repository before you make it public.**

`repo-public-check` looks for common publication mistakes: tracked `.env` files, credentials, private keys, personal absolute paths, localhost/internal URLs, oversized files, generated artifacts, missing OSS metadata, and sensitive-looking files that still exist in Git history.

```text
$ repo-public-check .
repo-public-check v0.1.0
Repository: /path/to/example
Scanned: 42 tracked file(s)

Findings
  ✗ Sensitive-looking file is tracked (.env)
    Remove the file from Git and rotate credentials if it contained secrets.
  ! Personal absolute path (src/config.py:18)
    Found a macOS user path; replace machine-specific paths with relative paths or placeholders.

Public Readiness
  Score: 70/100
  Blockers: 1
  Warnings: 1
  NOT READY — fix blockers before making the repository public
```

## Install

With `pipx`:

```bash
pipx install git+https://github.com/kantaro4123/repo-public-check.git
```

Or with `pip`:

```bash
python -m pip install git+https://github.com/kantaro4123/repo-public-check.git
```

Then run it inside any Git repository:

```bash
repo-public-check .
```

Python 3.10 or newer is required. The CLI has no runtime dependencies outside the Python standard library and Git.

## What it checks

| Check | Default severity |
| --- | --- |
| `.env`, private-key, certificate/key-store and credential-like filenames | Blocker |
| High-confidence GitHub/AWS/Slack/Stripe/Google credentials | Blocker |
| Private-key material | Blocker |
| Tracked files larger than 100 MiB | Blocker |
| Personal `/Users/...`, `/home/...`, or Windows user paths | Warning |
| `localhost`, private IPs and `.local` / `.internal` URLs | Warning |
| Tracked generated artifacts such as `node_modules`, virtualenvs and caches | Warning |
| Tracked files that are also ignored by `.gitignore` | Warning |
| Files larger than 10 MiB | Warning |
| Sensitive-looking filenames removed from HEAD but still present in Git history | Warning |
| Missing README, LICENSE or `.gitignore` | Warning |
| Missing `SECURITY.md` and remaining TODO/FIXME markers | Info |

Credential findings never print the matched secret value.

## JSON output

Use `--json` in CI or other tooling:

```bash
repo-public-check . --json
```

Example shape:

```json
{
  "ready": false,
  "score": 70,
  "summary": {
    "blockers": 1,
    "warnings": 1,
    "info": 0
  },
  "findings": []
}
```

## Strict mode

Warnings normally do not block publication. To make warnings fail CI too:

```bash
repo-public-check . --strict
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No blocker found |
| `1` | At least one blocker found, or a warning was found with `--strict` |
| `2` | The check could not run, for example because the path is not a Git repository |

## Scoring

The score is a quick readiness signal, not a security certification. Blockers carry a larger penalty than warnings, while informational findings do not lower the score. **A repository is considered ready when there are no definite blockers**, regardless of the numeric score.

## Git history

Removing a credential from the latest commit does not remove it from Git history. v0.1 checks historical *filenames* for sensitive-looking paths such as `.env` or private-key files and warns when one was deleted from the current tree.

It deliberately does not scan every historical blob for secrets yet; large repositories could make that expensive. If a real credential was ever committed, rotate it even after rewriting history.

## Privacy

All checks run locally. `repo-public-check` does not upload repository contents or send findings to a third-party service.

## Development

```bash
git clone https://github.com/kantaro4123/repo-public-check.git
cd repo-public-check
python -m pip install -e .
python -m unittest discover -s tests -v
repo-public-check .
```

CI tests Python 3.10 and 3.13 on both Linux and macOS, then smoke-tests the installed command.

## License

MIT
