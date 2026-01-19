# Test Scripts

This directory contains all test scripts for SCRYNET.

## Available Tests

- **`test_juice_shop.sh`** - Test with OWASP Juice-Shop
- **`test_dvwa.sh`** - Test with DVWA
- **`test_complex.sh`** - Complex end-to-end test with multiple profiles
- **`test_advanced.sh`** - Advanced multi-profile tests
- **`test_all_profiles.sh`** - Test all available profiles

## Usage

Run tests from the `tests/scripts/` directory:

```bash
cd tests/scripts
bash test_juice_shop.sh
```

Or with cost estimation:

```bash
cd tests/scripts
bash test_juice_shop.sh --estimate-only
```

## Output

Test results are saved to `../test-reports/` (relative to this directory).

