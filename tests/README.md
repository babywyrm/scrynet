# SCRYNET Test Suite

This directory contains the Python test suite for SCRYNET.

## Test Files

### Core Tests

- **`test_profiles.py`** - Tests for profile loading and validation
  - Profile file existence
  - Required placeholders
  - JSON structure requirements
  - Profile loading logic

- **`test_common.py`** - Tests for common utilities (`lib/common.py`)
  - JSON parsing from API responses
  - File scanning utilities
  - Retry decorator functionality
  - Code extension detection

- **`test_orchestrator.py`** - Tests for orchestrator functionality
  - Severity enum and ordering
  - Profile template loading
  - Profile placeholder validation

### Legacy/Reference Files

The following files are kept for reference but may be outdated:

- **`IMPROVEMENTS.md`** - Historical improvement notes from beta development
- **`REVIEW_STATE.md`** - Documentation for review state features (may need updates)
- **`SCRYNET_CONTEXT_README.md`** - Documentation for context library (see `lib/scrynet_context.py`)
- **`test_context_lib.py`** - Test for context library (may need path updates)
- **`scrynet_context_example.py`** - Example usage of context library

## Running Tests

### Run All Tests

```bash
# From the gowasp directory
python3 -m unittest discover tests -v
```

### Run Specific Test File

```bash
python3 -m unittest tests.test_profiles -v
python3 -m unittest tests.test_common -v
python3 -m unittest tests.test_orchestrator -v
```

### Run Specific Test Class

```bash
python3 -m unittest tests.test_profiles.TestProfiles -v
```

## Test Coverage

Current tests cover:
- ✅ Profile file validation
- ✅ Common utility functions
- ✅ Orchestrator initialization
- ✅ Severity filtering

Future test additions:
- [ ] Integration tests with mock API responses
- [ ] End-to-end workflow tests
- [ ] Payload generation tests
- [ ] Code annotation tests
- [ ] Report generation tests

## Notes

- Tests use `sys.path.insert(0, ...)` to import from parent directory
- Some tests may require virtual environment to be activated
- Legacy test files may need updates to reflect current codebase structure

