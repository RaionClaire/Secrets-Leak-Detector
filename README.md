# Secrets Leak Detector (Go) — GitHub Integration

Detect leaked credentials (API keys, tokens, private keys, hardcoded passwords) in:
- Full repository snapshots (`mode=repo`)
- Pull request diffs (`mode=pr`, scans only added `+` lines)

Ships with GitHub Actions integration to fail checks and optionally comment on PRs with masked findings.

---

## Features
- Regex rules for common secrets (AWS, GitHub PAT, Google API key, Slack tokens, private key blocks, etc.)
- Optional high-entropy detection for random-looking strings
- `.secretsignore` to skip files/dirs; `.secretscan.yml` to tune thresholds and limits
- PR auto-commenting (masked values) and CI fail on findings

---

## Install

```bash
go install github.com/raionclaire/secrets-leak-detector/cmd/secretscan@latest
```

## Usage (local)

Full repo scan (fails on findings by default):
```bash
go run ./cmd/secretscan -mode=repo -path=. -format=text
```

JSON output for tooling:
```bash
go run ./cmd/secretscan -mode=repo -path=. -format=json
```

Disable failure on findings while iterating:
```bash
go run ./cmd/secretscan -mode=repo -path=. -fail=false
```

## Configuration

`.secretscan.yml` (defaults shown):
```yaml
exclude_dirs:
	- vendor
	- node_modules
	- .git
	- dist
	- build

max_file_size_bytes: 1048576

enable_entropy: true
entropy_threshold: 4.7
min_entropy_len: 24

allowlist_regex: ""
```

`.secretsignore` examples:
```gitignore
vendor/**
node_modules/**
dist/**
build/**
.git/**
```

## GitHub Actions

Create `.github/workflows/secrets-scan.yml`:
```yaml
name: secrets-scan
on:
	pull_request:
	push:
		branches: [main]

jobs:
	scan:
		runs-on: ubuntu-latest
		steps:
			- uses: actions/checkout@v4
			- uses: actions/setup-go@v5
				with:
					go-version: '1.22'
			- name: Run secret scan
				run: go run ./cmd/secretscan -mode=repo -path=. -format=json
```

- Use `-fail=false` if you prefer a non-blocking report during rollout.
- For PR comments, provide `GITHUB_TOKEN` (Actions sets it) and run on `pull_request`.

## Exit codes
- `0`: no findings (or `-fail=false` set)
- `1`: findings detected and `-fail=true`
- `2`: usage or runtime error

## Forks and module path
The module path is `github.com/raionclaire/secrets-leak-detector` (see `go.mod`). If you fork and publish under a different GitHub account, update the module path and imports to match your fork before distributing.
