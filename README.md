# Secrets Leak Detector (Go) — GitHub Integration

Secrets Leak Detector is a Go-based tool that detects leaked credentials (API keys, tokens, private keys, hardcoded passwords) in:
- **Full repository scan (HEAD)**
- **Pull Request diff scan** (only newly added `+` lines)

This project integrates with GitHub via **GitHub Actions** and uses the **GitHub API** to automatically comment on pull requests when potential secrets are detected.

---

## Features (MVP)

- ✅ Regex rules for common secrets (AWS, GitHub PAT, Google API key, Slack tokens, private key blocks, etc.)
- ✅ Optional high-entropy detection for suspicious random-looking strings
- ✅ `.secretsignore` support to exclude files/folders
- ✅ `.secretscan.yml` configuration (entropy thresholds, max file size, excluded dirs)
- ✅ PR auto-commenting (masked output, never prints full secret values)
- ✅ Fails CI when secrets are found (prevents merges when required checks are enabled)

---

## How It Works

### On `push`
Runs a **full repository scan** against the current HEAD.

### On `pull_request`
Scans the **PR patch/diff** (only the newly added lines) and:
- posts a PR comment listing findings (masked)
- fails the workflow if any secret is detected

---

## Quick Start (Local)

### Requirements
- Go **1.22+**

### Run a full repo scan
```bash
go run ./cmd/secretscan -mode=repo -path=. -fail=true
