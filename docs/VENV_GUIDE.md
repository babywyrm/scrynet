# Virtual Environment Guide

SCRYNET uses a Python virtual environment to manage dependencies. This guide explains how to set it up and use it.

## Quick Setup

### First Time Setup

```bash
# Run the automated setup script
./setup.sh

# This will:
# 1. Create a virtual environment (.venv)
# 2. Install all required dependencies
# 3. Show you how to activate it
```

### Activating the Virtual Environment

**Option 1: Use the helper script**
```bash
source activate.sh
```

**Option 2: Manual activation**
```bash
source .venv/bin/activate
```

**You'll know it's activated when you see `(.venv)` in your prompt:**
```bash
(.venv) tms in ~/gowasp/gowasp on main ● λ
```

## Common Issues

### "No module named 'typing_inspection'"

**Problem:** You're running Python outside the virtual environment.

**Solution:**
```bash
# Activate the venv first
source .venv/bin/activate

# Then run your command
python3 scrynet.py hybrid ...
```

### "pip: command not found" or "External manager" error

**Problem:** System Python is protected (PEP 668).

**Solution:** Use the virtual environment - it has its own pip:
```bash
source .venv/bin/activate
pip install -r requirements.txt  # Works inside venv
```

### Virtual environment not found

**Problem:** `.venv` directory doesn't exist.

**Solution:**
```bash
# Run setup script
./setup.sh

# Or create manually
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Daily Usage

### Starting a New Session

```bash
cd /Users/tms/gowasp/gowasp
source .venv/bin/activate  # Activate venv
# Now you can run SCRYNET commands
```

### Checking if Venv is Active

```bash
which python
# Should show: /Users/tms/gowasp/gowasp/.venv/bin/python

# Or check your prompt for (.venv)
```

### Deactivating

```bash
deactivate
```

## Verification

After activating, verify everything works:

```bash
source .venv/bin/activate

# Check Python location
which python
# Should be: .../gowasp/.venv/bin/python

# Test imports
python -c "import typing_inspection; print('✓ typing_inspection OK')"
python -c "import anthropic; print('✓ anthropic OK')"
python -c "import rich; print('✓ rich OK')"

# Test SCRYNET
python3 scrynet.py --help
```

## Tips

1. **Add to your shell config** (optional):
   ```bash
   # Add to ~/.zshrc or ~/.bashrc
   alias scrynet-activate='cd /Users/tms/gowasp/gowasp && source .venv/bin/activate'
   ```

2. **Use the helper scripts:**
   - `./setup.sh` - Initial setup
   - `source activate.sh` - Quick activation

3. **Always activate before running:**
   - If you see import errors, check if venv is active
   - Look for `(.venv)` in your prompt

4. **Keep dependencies updated:**
   ```bash
   source .venv/bin/activate
   pip install --upgrade -r requirements.txt
   ```

## Troubleshooting

### Recreate Virtual Environment

If something goes wrong, you can recreate it:

```bash
# Remove old venv
rm -rf .venv

# Run setup again
./setup.sh
```

### Check Installed Packages

```bash
source .venv/bin/activate
pip list
```

### Verify Requirements

```bash
source .venv/bin/activate
pip check
```

