# GitHub Workflows

All GitHub Actions workflows in this repository are powered by modular configuration files – your one-stop shop for tweaking CI/CD behavior without touching a single YAML file!

<br>

## The Workflow Control Center

**Configuration Files:**
- **[`.github/env/`](../env/README.md)** – Modular environment configuration split into domain-specific files loaded in numeric order

These configuration files control everything from:
- **Go version matrix** (test on multiple versions or just one)
- **Runner selection** (Ubuntu or macOS, your wallet decides)
- **Feature toggles** (coverage, fuzzing, linting, race detection, benchmarks)
- **Security tool versions** (gitleaks, nancy, govulncheck)
- **Auto-merge behaviors** (how aggressive should the bots be?)
- **PR management rules** (size labels, auto-assignment, welcome messages)

<br>

## Workflows

| Workflow | Description |
|----------|-------------|
| [auto-merge-on-approval.yml](../workflows/auto-merge-on-approval.yml) | Automatically merges PRs after approval and all required checks, following strict rules. |
| [codeql-analysis.yml](../workflows/codeql-analysis.yml) | Analyzes code for security vulnerabilities using [GitHub CodeQL](https://codeql.github.com/). |
| [docker-publish.yml](../workflows/docker-publish.yml) | Builds the service container image and publishes it to [GHCR](https://github.com/bsv-blockchain/go-private-backup-cache/pkgs/container/go-private-backup-cache) (`latest`, commit SHA, and release tags). |
| [dependabot-auto-merge.yml](../workflows/dependabot-auto-merge.yml) | Automatically merges [Dependabot](https://github.com/dependabot) PRs that meet all requirements. |
| [fortress.yml](../workflows/fortress.yml) | Runs the GoFortress security and testing workflow, including linting, testing, releasing, and vulnerability checks. |
| [postgres.yml](../workflows/postgres.yml) | Runs the full Go test suite against a real PostgreSQL service, so the Postgres-gated store tests run in CI. |
| [pull-request-management.yml](../workflows/pull-request-management.yml) | Labels PRs by branch prefix, assigns a default user if none is assigned, and welcomes new contributors with a comment. |
| [scorecard.yml](../workflows/scorecard.yml) | Runs [OpenSSF](https://openssf.org/) Scorecard to assess supply chain security. |
| [stale.yml](../workflows/stale-check.yml) | Warns about (and optionally closes) inactive issues and PRs on a schedule or manual trigger. |
| [sync-labels.yml](../workflows/sync-labels.yml) | Keeps GitHub labels in sync with the declarative manifest at [`.github/labels.yml`](../labels.yml). |
| [ts.yml](../workflows/ts.yml) | Builds and tests the TypeScript client, then runs the cross-language interop suite against a live Go server. |

<br>

---

[← Back to README](../../README.md)
