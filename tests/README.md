# Agent Smith Test Suite

Python test suite for Agent Smith core functionality.

## Running Tests

### Quick Test
```bash
source scripts/activate.sh
python3 tests/test_imports.py
```

### All Tests
```bash
python3 -m unittest discover tests -v
```

### Specific Test Files
```bash
python3 -m unittest tests.test_common -v
python3 -m unittest tests.test_orchestrator -v
python3 -m unittest tests.test_profiles -v
python3 -m unittest tests.test_integration -v
```

### Specific Test Classes
```bash
python3 -m unittest tests.test_common.TestNormalizeFinding -v
python3 -m unittest tests.test_integration.TestNormalizationIntegration -v
```

## Test Files

- `test_common.py` - Tests for `lib/common.py` utilities (33 tests)
- `test_orchestrator.py` - Tests for orchestrator functionality (5 tests)
- `test_profiles.py` - Tests for profile loading (9 tests)
- `test_integration.py` - Integration and workflow tests (5 tests)
- `test_presets.py` - Preset system and smart defaults (14 tests)
- `test_universal_detector.py` - Universal tech detection (10 tests)
- `test_advanced_features.py` - Quick wins, file grouping, etc. (11 tests)
- `test_mcp_tools.py` - MCP server tools and handlers (10 tests)
- `test_imports.py` - Quick import verification
- `test_context_lib.py` - Context/caching tests
- `test_review_state.py` - Review state and cache management (13 tests)
- `test_prioritization.py` - AI prioritization logic (20 tests)
- `test_edge_cases.py` - Edge cases and error handling (31 tests)

## Test Coverage

Current coverage: **223 tests passing (100%)** ✅

### Covered
✅ Finding normalization (8 tests)
✅ Recommendation extraction (1 test)
✅ Line number extraction (5 tests)
✅ Safe file reading (3 tests)
✅ Error classes (2 tests)
✅ API error handling (5 tests) ✨ FIXED
✅ JSON parsing (5 tests)
✅ Integration workflows (5 tests)
✅ Orchestrator functionality (5 tests)
✅ Profile loading (9 tests)
✅ Preset system (6 tests)
✅ Smart defaults (5 tests)
✅ Universal tech detection (10 tests)
✅ Quick wins logic (4 tests)
✅ File grouping (2 tests)
✅ Framework-aware prioritization (2 tests)
✅ Color coding (1 test)
✅ Smart top-n (2 tests)
✅ **Review state lifecycle (4 tests)** ⭐ NEW
✅ **Review state checkpoints (2 tests)** ⭐ NEW
✅ **Cache management (3 tests)** ⭐ NEW
✅ **Cost tracking (2 tests)** ⭐ NEW
✅ **Directory fingerprinting (2 tests)** ⭐ NEW
✅ **AI prioritization (20 tests)** ⭐ NEW
✅ **Edge cases and error handling (31 tests)** ⭐ NEW

### Test Targets

Real vulnerability test applications in `test_targets/`:
- DVWA - Damn Vulnerable Web Application
- juice-shop - OWASP Juice Shop
- WebGoat - OWASP WebGoat

## MCP Tester Scanner

The MCP server exposes `scan_mcp` to security-scan remote MCP servers. Two ways to exercise it:

| Method | Command |
|--------|---------|
| **Interactive shell** | `./scripts/run_mcp_shell.sh` → at `mcp>` type `scan_mcp 9001` or `dvmcp` |
| **Automated test** | `AGENTSMITH_MCP_TEST_TARGET=http://localhost:2266/sse ./scripts/run_mcp_tests.sh` (adds scan_mcp test) |
| **DVMCP suite** | `./tests/test_dvmcp.sh` or `./tests/test_dvmcp.sh 1 8` (requires DVMCP cloned at `tests/test_targets/DVMCP`) |
| **DVMCP JSON** | `./tests/test_dvmcp.sh --json` — JSON scoreboard for CI/regression |

See [mcp_server/README.md](../mcp_server/README.md) and [docs/MCP_SCANNING.md](../docs/MCP_SCANNING.md) for full docs.

## Shell Scripts

**Project scripts** (`scripts/`):
- `run_mcp_tests.sh` - Start MCP server (if needed) and run test suite
- `run_mcp_shell.sh` - One-command setup + MCP server + interactive client

**Integration test scripts** (`tests/scripts/`):
- `test_advanced.sh` - Advanced feature tests
- `test_complex.sh` - Complex multi-profile tests
- `test_all_profiles.sh` - Test all profiles
- `test_juice_shop.sh` - Test juice-shop scan

Run with:
```bash
source scripts/activate.sh
./scripts/run_mcp_tests.sh
# or for interactive MCP client:
./scripts/run_mcp_shell.sh
```

## Notes

- Tests use virtual environment (`.venv`)
- Some tests require `CLAUDE_API_KEY` for API integration tests
- Static tests work without API key
