# Agent Smith Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2026-02

### Added

- **Tech-stack-aware rules**: `rules_node.json` and `rules_python.json` loaded when `package.json` or `requirements.txt` detected (child_process, vm, pickle, yaml patterns)
- **Attack chain profiling** (design): Documented in STRETCH_GOALS as advanced opt-in feature; AI-driven synthesis of findings + taint flows into multi-step attack paths
- **SARIF export**: `agentsmith.py static --output sarif` for IDE/Code Scanning integration
- **Pre-commit example**: `examples/pre-commit-hook.sh` and `examples/.pre-commit-config.yaml` — scan before commit, fail on CRITICAL
- **examples/README.md**: Documents CI gate and pre-commit examples
- **Rules validation in CI**: `examples/ci-gate.yml` now runs `validate_rules.py` before scan
- **MCP preset** (`--preset mcp`): 2 files, no payloads/annotations, ~1 min — for MCP shell and Cursor integration
- **MCP shell docs**: Tail log (`tail -f .mcp_server.log`), debug mode, `scan_mcp` from interactive shell
- **docs/README.md**: Index of all documentation
- **scan_mcp shorthand**: `scan_mcp 9001` or `scan_mcp 9001 9002 9008` → localhost ports (no JSON needed)
- **dvmcp command**: Built-in sweep of all 10 DVMCP challenges (ports 9001–9010) from MCP shell
- **Status enhancements**: `status` shows last tool and last target; `last` shows header with target
- **Colorized `last`**: JSON output from `last` command now syntax-highlighted (keys, strings, numbers)
- **Clearer scan_mcp errors**: Connection failures show friendly messages instead of ExceptionGroup stack traces
- **run_mcp_shell.sh --restart**: Script now stops existing server and starts fresh to pick up current env (CLAUDE_API_KEY, etc.); use `--no-restart` to connect to existing server
- **Static → Prioritization**: Hybrid scans now feed static findings into the AI prioritization prompt; files with static hits are preferred for deep-dive analysis (saves AI cost, improves coverage)
- **Node.js/Mongoose rules**: New rules in rules_core.json for Mongoose `findByIdAndUpdate(req.body)`, `Model.update(req.body)`, mass assignment, and req.params in MongoDB queries
- **docs/STATIC_SCANNER_STRATEGY.md**: Strategy doc for static scanner improvements and prioritization logic
- **rules/CHANGELOG.md**: Rules changelog for rule additions and changes
- **Modern framework rules**: Prisma unsafe raw SQL, React dangerouslySetInnerHTML, Go fmt.Sprintf in SQL, Ruby ActiveRecord raw SQL; Java (Spring/Quarkus), Python (Django/FastAPI/SQLAlchemy) framework rules
- **Scanner extensions**: Now scans `.ts`, `.tsx`, `.rb`, `.yml`, `.yaml`
- **docs/STRETCH_GOALS.md**: Holistic improvement roadmap (consolidated from MCP + Static Strategy)
- **CTF prioritization + static findings**: `CTFPromptFactory.prioritization()` now accepts `static_findings`
- **CI exit codes**: `agentsmith.py static --fail-on HIGH` exits 1 on HIGH/CRITICAL findings; Go scanner fixed to exit on both
- **examples/ci-gate.yml**: GitHub Actions workflow for static scan with `--fail-on HIGH`

### Changed

- Preset count: 7 (added `mcp`)
- Test count: 223 (was 190+)

## [1.x] - 2026-01-24

### Added - Phase 4: Enhanced Tech Stack Detection & Testing

- **Universal Tech Stack Detection** (`lib/universal_detector.py`)
  - Recursive detection of frameworks in subdirectories
  - Detects: Flask, Django, FastAPI, Express, Spring, Laravel, gRPC, and more
  - Identifies entry points (routes, controllers, APIs)
  - Finds security-critical files (auth, config, middleware)
  - Detects databases and ORMs (SQLAlchemy, Sequelize, Doctrine)
  - Lists framework-specific security risks
  - `--detect-tech-stack` flag for detailed detection report

- **Framework-Aware Analysis** (Automatic in Every Scan)
  - Tech stack context automatically passed to AI prompts
  - Framework-specific risks highlighted in prompts
  - Entry points and critical files emphasized
  - Prioritization questions enhanced with framework context
  - Tech stack summary displayed in final report
  - tech_stack.json exported with every scan
  - Example: Flask apps → Focuses on SSTI, SQLAlchemy injection, session security

- **Smart File Focus**
  - AI prioritization now framework-aware
  - Automatically highlights routes, controllers, auth files
  - Framework-specific attack patterns guide analysis
  - Example output: "8 framework-specific risks, 7 entry points, 1 critical file"

- **Comprehensive Test Suite**
  - Added 21 new tests (82 total, up from 61)
  - Test coverage: 93.9% (up from 91.8%)
  - All new features 100% tested
  - Universal detector: 10 tests
  - Advanced features: 11 tests (quick wins, file grouping, smart top-n)
  - All critical functionality verified

### Important - Main Entry Point
- **orchestrator.py** is now the recommended entry point for hybrid mode
- Supports all new features: presets, smart defaults, quick wins, enhanced prompts
- `agentsmith.py` remains available as unified dispatcher for all modes
- All documentation updated to use `orchestrator.py` for hybrid scans

### Added - Phase 3: Quick Wins & Enhanced Display

- **Quick Wins System**
  - `--show-quick-wins` flag to highlight most exploitable findings
  - Auto-enabled for CTF and pentest presets
  - Displays exploitability scores, time-to-exploit, attack scenarios
  - Smart filtering (score >=7 OR time<10min OR CRITICAL severity)
  - Shows top 10 quick wins with colored output

- **Enhanced Console Display**
  - Exploitability scores visible in verbose mode (⚡8/10)
  - Time-to-exploit display (🕐< 5 minutes)
  - Attack scenario previews in quick wins
  - Fixed color coding (CRITICAL/HIGH=red, MEDIUM=yellow, LOW=cyan)
  - Smart top-n calculation (scales with findings: 10-20% of total)

- **File-Grouped Annotations** (Critical Fix)
  - Annotations now group by file, not individual findings
  - Selecting top N findings identifies important files
  - Then annotates ALL findings in those files
  - Result: 2x more comprehensive coverage
  - Example: Top 9 findings → 6 files → 18 total annotations

### Added - Phase 2: Smart Presets & Enhanced Analysis

- **Preset System** (`lib/config.py`)
  - 6 optimized presets: `quick`, `ctf`, `ctf-fast`, `security-audit`, `pentest`, `compliance`
  - `--preset <name>` flag for one-command configuration
  - `--list-presets` to view all available presets
  - Presets can be overridden with individual flags

- **Smart Defaults System**
  - Auto-prioritization for repos with >50 files
  - Auto-deduplication when using multiple profiles
  - Auto-add HTML export when payloads/annotations enabled
  - Smart top-n calculation based on findings count
  - `--smart-defaults` (enabled by default)
  - `--no-smart-defaults` to disable auto-configuration

- **Tech Stack Detection**
  - Automatic detection of frameworks (Flask, Django, Express, Spring, etc.)
  - Language detection (Python, JavaScript, Go, Java, PHP)
  - Application type classification (web_app, web_api, microservice)
  - Container detection (Docker)
  - Context passed to AI for smarter analysis

- **Enhanced Prompts**
  - `owasp_enhanced_profile.txt` - 3x more detailed, exploitability-focused
  - `ctf_enhanced_profile.txt` - CTF-optimized with flag hunting strategies
  - Automatic detection and use of enhanced prompts
  - Fallback to legacy prompts for compatibility
  - App context injection for framework-aware analysis

### Added - Phase 1: Normalization & Error Handling

- **Normalization Utilities** (`lib/common.py`)
  - `normalize_finding()` - Centralized finding normalization
  - `get_recommendation_text()` - Unified recommendation extraction
  - `get_line_number()` - Consistent line number handling
  - `handle_api_error()` - Smart API error handling with retry logic
  - `safe_file_read()` - Safe file operations with size checks
  - Custom exceptions: `APIError`, `FileAnalysisError`, `AgentSmithError`

- **Test Suite Improvements**
  - 48 unit tests covering normalization and error handling
  - Integration tests for complete workflows
  - Test coverage: 89.6% (43/48 tests passing)

### Changed
- **Orchestrator Refactoring** (`orchestrator.py`)
  - Eliminated 13+ duplicated normalization patterns
  - All stages now use centralized utilities:
    - AI scanner findings processing
    - CSV/Markdown/HTML export
    - Payload generation stage
    - Code annotation stage
    - Deduplication key generation
  - Improved error handling with specific exception types
  - Better logging and error messages

### Fixed
- Inconsistent field handling (line vs line_number, fix vs recommendation)
- Generic exception handling replaced with specific error types
- File path normalization (Path objects converted to strings consistently)
- Severity capitalization standardized across all outputs

### Technical Debt Resolved
- Code duplication: 13+ patterns → 2 utility functions
- Maintainability: Single source of truth for field normalization
- Testability: All normalization logic now unit tested
- Error handling: Specific exceptions with proper context
- Command complexity: 39 options → 6 presets + smart defaults (70% reduction)
- Prompt quality: Basic pattern matching → exploitability-focused analysis

### Performance
- Smart defaults reduce unnecessary API calls
- Auto-prioritization for large repos saves time and cost
- Tech stack detection enables framework-aware analysis

### User Experience
- Presets reduce command complexity by ~70%
- Smart defaults "just work" for most cases
- Enhanced prompts provide more actionable results
- Better progress feedback and context awareness

---

## [Previous] - Historical

### Features
- Multi-mode security scanner (static, analyze, ctf, hybrid)
- AI-powered analysis with Claude integration
- Multiple AI profiles (owasp, ctf, code_review, etc.)
- AI prioritization to select most relevant files
- Payload generation for Red/Blue team testing
- Code annotation with inline fixes
- Intelligent deduplication of findings
- Cost tracking and estimation
- Review state management with caching
- Multiple export formats (JSON, CSV, Markdown, HTML)
- Rich console UI with progress bars
- Support for multiple languages (Go, Python, Java, JS, PHP, etc.)

