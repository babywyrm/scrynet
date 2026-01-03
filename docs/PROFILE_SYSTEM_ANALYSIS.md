# Profile System Analysis & Improvement Plan

## Current State

### Existing Profiles (3)
1. **`owasp`** - OWASP Top 10 security analysis
   - Location: `prompts/owasp_profile.txt`
   - Used in: `orchestrator.py` (hybrid mode)
   - Focus: OWASP Top 10 vulnerabilities (A01-A10)

2. **`attacker`** - Threat modeling/penetration testing
   - Location: `prompts/attacker_profile.txt`
   - Used in: `orchestrator.py` (when `--threat-model` flag is used)
   - Focus: Attack scenarios, entry points, data flow analysis

3. **`performance`** - Performance anti-patterns
   - Location: `prompts/performance_profile.txt`
   - Used in: `orchestrator.py` (hybrid mode)
   - Focus: Performance issues (N+1 queries, memory leaks, etc.)

### How Profiles Work Currently

**In `orchestrator.py` (hybrid mode):**
- Profiles are loaded from `prompts/{profile}_profile.txt` files
- Each profile is a simple text template with placeholders: `{file_path}`, `{language}`, `{code}`
- Multiple profiles can be run (comma-separated: `--profile owasp,performance`)
- Each profile analyzes every file independently
- Results are merged with `source: 'claude-{profile}'` tag

**In `ctf_analyzer.py`:**
- Uses `CTFPromptFactory` class (not the profile system)
- Has its own CTF-focused prompts
- Not integrated with the profile system

**In `smart_analyzer.py`:**
- Uses `PromptFactory` class (not the profile system)
- Has generic security prompts
- Not integrated with the profile system

## Issues & Limitations

1. **Fragmentation**: Profile system only works in `orchestrator.py`, not unified across all modes
2. **Limited Profiles**: Only 3 profiles exist (OWASP, attacker, performance)
3. **No CTF Profile**: CTF mode uses separate prompts, not a profile
4. **No Code Review Profile**: Missing code review/quality focus
5. **No Compliance Profiles**: Missing SOC2, PCI-DSS, HIPAA, etc.
6. **No Modern Security Profile**: Missing modern practices (zero-trust, supply chain, etc.)
7. **Simple Templates**: Profiles are just text files, no metadata or configuration
8. **No Profile Validation**: No way to check if profiles are compatible or conflict
9. **No Profile Documentation**: Users don't know what each profile does
10. **No Profile Examples**: No guidance on when to use which profile

## Proposed Improvements

### Phase 1: Expand Profile Library

Create new profiles:

1. **`ctf`** - CTF-focused vulnerability discovery
   - Focus: Exploitable vulnerabilities, flags, quick wins
   - Use case: CTF challenges, bug bounties, penetration testing

2. **`code_review`** - Code quality and best practices
   - Focus: Code quality, maintainability, best practices, technical debt
   - Use case: Pre-merge reviews, code quality audits

3. **`soc2`** - SOC 2 compliance
   - Focus: Access controls, encryption, monitoring, availability
   - Use case: SOC 2 audits, compliance reviews

4. **`pci`** - PCI-DSS compliance
   - Focus: Payment data handling, encryption, access controls
   - Use case: Payment processing applications

5. **`modern`** - Modern security practices
   - Focus: Zero-trust, supply chain security, cloud-native, DevSecOps
   - Use case: Modern applications, cloud deployments

6. **`compliance`** - General compliance (HIPAA, GDPR, etc.)
   - Focus: Data privacy, encryption, access controls, audit trails
   - Use case: Healthcare, financial, EU applications

### Phase 2: Profile System Enhancement

1. **Profile Metadata System**
   - Add `profiles/{profile}.json` with metadata:
     ```json
     {
       "name": "owasp",
       "display_name": "OWASP Top 10",
       "description": "Focuses on OWASP Top 10 security vulnerabilities",
       "use_cases": ["Security audits", "Vulnerability assessments"],
       "focus_areas": ["A01-A10", "Injection", "Authentication"],
       "compatible_with": ["performance", "code_review"],
       "conflicts_with": [],
       "template_file": "prompts/owasp_profile.txt"
     }
     ```

2. **Unified Profile System**
   - Create `lib/profile_manager.py` to handle profiles across all modes
   - Integrate profiles into `ctf_analyzer.py` and `smart_analyzer.py`
   - Allow profiles to be used in all modes

3. **Profile Validation**
   - Check for conflicting profiles
   - Validate profile combinations
   - Warn about incompatible profiles

4. **Profile Documentation**
   - Add `PROFILES.md` with descriptions and examples
   - Update help text with profile descriptions
   - Add examples for each profile

### Phase 3: Advanced Features

1. **Custom Profiles**
   - Allow users to create custom profiles
   - Support for user-defined prompt templates

2. **Profile Presets**
   - Pre-defined combinations: `--preset security-audit` (owasp + code_review)
   - Pre-defined combinations: `--preset compliance` (soc2 + pci + compliance)

3. **Profile-Specific Output**
   - Different output formats per profile
   - Profile-specific report sections

## Implementation Priority

1. **High Priority** (Do First):
   - Create `ctf` profile (unify CTF mode with profile system)
   - Create `code_review` profile
   - Create `modern` profile
   - Add profile metadata system

2. **Medium Priority**:
   - Create compliance profiles (`soc2`, `pci`, `compliance`)
   - Unify profile system across all modes
   - Add profile documentation

3. **Low Priority**:
   - Custom profiles
   - Profile presets
   - Advanced validation

## Next Steps

1. Review and approve this plan
2. Start with creating the new profiles (ctf, code_review, modern)
3. Add profile metadata system
4. Update documentation
5. Test with vulnerable repos

