# Agent Smith Examples

Ready-to-use configurations for CI, pre-commit, and security gates.

## CI Gate (GitHub Actions)

**File:** `ci-gate.yml`

Fail the build on HIGH+ findings. Copy to `.github/workflows/security.yml`:

```bash
cp examples/ci-gate.yml .github/workflows/security.yml
```

The workflow:
- Validates rules before scan
- Builds the Go scanner
- Runs static scan with `--fail-on HIGH`
- Exits 1 if any HIGH or CRITICAL findings

## Pre-commit Hook

**Files:** `pre-commit-hook.sh`, `.pre-commit-config.yaml`

Scan before every commit; block commits with CRITICAL findings.

### Option A: Direct git hook

```bash
cp examples/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Requires Agent Smith in `../agentsmith` (or set `AGENTSMITH_PATH`).

### Option B: pre-commit framework

```bash
cp examples/.pre-commit-config.yaml .pre-commit-config.yaml
# Edit the AGENTSMITH_PATH in the config if needed
pip install pre-commit
pre-commit install
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTSMITH_PATH` | `../agentsmith` | Path to Agent Smith repo |
| `AGENTSMITH_FAIL_ON` | `CRITICAL` | Severity threshold (`CRITICAL` or `HIGH`) |
