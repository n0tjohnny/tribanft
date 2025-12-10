# TRIBANFT AGENT — SONNET 4.5 RAG AUTHORITY (TOKEN-OPTIMIZED)

## MODE SYSTEM

**MODE: FULL | ANALYSIS | LIGHT**  
**REASON:** [why this mode was chosen]

- **FULL** = Code edits and modifications
- **ANALYSIS** = Reasoning and review only, no modifications
- **LIGHT** = Documentation, formatting, and spelling only

## AUTHORITY

**Truth source is exclusively RAG-retrieved project material.** No external knowledge, defaults, or assumptions are valid. Every statement must be classifiable as:
- **FACT** - Directly observed from repository files
- **INFERENCE** - Logical conclusion from observed facts
- **ASSUMPTION** - Unverified hypothesis (must be labeled as such)

## MANDATORY EVIDENCE RULE

**Never assume. Always `view` before acting.**

Any unviewed behavior is unknown and cannot be modified or relied upon. All code changes must be preceded by viewing the target file to understand current implementation.

## EDIT ATOM

**Only allowed mutation primitive:**
```
str_replace(path, old_str, new_str, desc)
```

**Rules:**
- Extract the exact string first
- Preserve whitespace and structure
- One logical change per invocation
- No regeneration, no rewrites, no refactors unless explicitly scoped

## CANONICAL FLOW

```
view → retrieve authoritative context via RAG → plan → str_replace(minimal) → verify → document
```

## MODE CONSTRAINTS

### FULL Mode
1. **view** - Examine target files and context
2. **verify dependencies via RAG** - Confirm all related components
3. **plan** - Outline minimal changes required
4. **str_replace** - Apply surgical edits
5. **confirm** - Validate changes don't break existing behavior

**Preservation requirements:**
- All existing patterns including logging, errors, and security logic
- If uncertainty exists, halt and request evidence

### ANALYSIS Mode
- Explain, review, or plan only
- **Zero modifications**
- Speculation must be labeled clearly

### LIGHT Mode
- Documentation, spelling, formatting only
- **No logic or structural changes**

## PROHIBITED BEHAVIOR

❌ **Never do these:**
- Solving a single delta with complete rewrites
- Assuming behavior without direct view
- Skipping dependency validation
- Batching unrelated edits
- Acting under probability or intuition

## DOCUMENTATION CONTRACT

Every change must document:

```
FILE: [path]
TYPE: feature|fix|refactor|docs
BEFORE→AFTER: [behavioral delta]
DEPS(RAG): [authoritative files consulted]
ROLLBACK: [explicit reversal instructions]
```

## COMMUNICATION STANDARDS

**Status Updates:**
```
NEED: [missing evidence]
RISK: [impact assessment]
CHANGE: [path] | [scope] | [impact] | REV:[yes/how]
```

## PROJECT SECURITY CONTEXT (RAG-VERIFIED ONLY)

**System Architecture:**
System operates as a coordinated security pipeline across:
- CrowdSec
- NFTables
- Fail2Ban
- Geolocation services
- Persistent IP intelligence stores at 36k+ scale

**Security Properties (Observable Mechanisms Only):**
Security properties are enforced through observable mechanisms only. The following must remain invariant unless the enforcing code is explicitly viewed and validated:

- Thread safety
- Atomicity
- Rate limiting
- Whitelist precedence
- Timestamp integrity
- Corruption resistance
- Input validation

**No implicit guarantees exist.** All security assumptions must be verified through code inspection.

## AUTHORITATIVE TARGETS

When working with this repository, these are the critical components:

- **Config handlers** - Configuration management and validation
- **Blocking logic** - IP blocking and firewall integration
- **Synchronization paths** - NFTables, CrowdSec, Fail2Ban coordination
- **Log analyzers** - Security event parsing and detection
- **Investigators** - IP intelligence and geolocation
- **Storage layers** - File-based and SQLite persistence
- **APIs** - External service integrations
- **Operational logs** - Audit trails and debugging information

## END-TO-END WORKFLOW

**Standard operating procedure:**

```
1. Request → Receive task or issue
2. Classify → Determine MODE (FULL, ANALYSIS, LIGHT)
3. View → Examine all relevant files
4. RAG Retrieve → Gather authoritative context
5. Plan → Design minimal changes
6. str_replace → Apply surgical edits
7. Verify → Confirm correctness
8. Document → Record changes per contract
```

## EXAMPLES

### Example: FULL Mode Operation

```
MODE: FULL
REASON: Bug fix in IP blocking logic

1. view /home/runner/work/tribanft/tribanft/bruteforce_detector/managers/blacklist_manager.py
2. RAG: Review related detectors and synchronization code
3. Plan: Fix off-by-one error in threshold calculation
4. str_replace(
     path="/home/runner/work/tribanft/tribanft/bruteforce_detector/managers/blacklist_manager.py",
     old_str="if event_count > threshold:",
     new_str="if event_count >= threshold:",
     desc="Fix threshold comparison to include edge case"
   )
5. Verify: Test with threshold boundary values
6. Document:
   FILE: bruteforce_detector/managers/blacklist_manager.py
   TYPE: fix
   BEFORE→AFTER: Changed > to >= for inclusive threshold check
   DEPS(RAG): detectors/prelogin_detector.py, config.py
   ROLLBACK: Revert >= back to >
```

### Example: ANALYSIS Mode Operation

```
MODE: ANALYSIS
REASON: Code review requested, no modifications needed

1. view target files
2. RAG: Gather context from related modules
3. Analyze: Identify patterns, potential issues
4. Report: Structured findings with evidence
   - FACT: Function X uses non-atomic file operations
   - INFERENCE: Could cause race condition under load
   - ASSUMPTION: System runs multi-threaded (needs verification)
```

### Example: LIGHT Mode Operation

```
MODE: LIGHT
REASON: Documentation update only

1. view README.md
2. Plan: Fix typos and formatting
3. str_replace(
     path="/home/runner/work/tribanft/tribanft/README.md",
     old_str="protectiong against",
     new_str="protection against",
     desc="Fix typo in overview section"
   )
4. No behavioral changes, no testing required
```

## INTEGRATION WITH REPOSITORY

This document is referenced by:
- `.github/workflows/claude-code-review.yml` - Automated code review guidance
- `.github/workflows/claude.yml` - Interactive Claude agent behavior

All AI agents working on this repository should follow these guidelines to ensure:
- Minimal, surgical changes
- Evidence-based modifications
- Security-aware development
- Consistent code quality
- Auditable change history

## VERSION

**Version:** 1.0  
**Last Updated:** 2025-12-10  
**Applies To:** All AI agents working on tribanFT repository
