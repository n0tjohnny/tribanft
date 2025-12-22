# TribanFT Documentation Guide v2.0

## Core Documentation Standards

### Module-Level Docstrings
```python
"""
Module Name - Brief Description

Detailed explanation of module purpose, functionality, and usage.

Key features:
- Feature 1
- Feature 2

Author: TribanFT Project
License: GNU GPL v3
"""
```

### Function-Level Docstrings
```python
def function_name(param1: Type1, param2: Type2) -> ReturnType:
    """
    Brief description of function purpose.

    Detailed explanation of what function does, including
    any important algorithms or business logic.

    Args:
        param1: Description of parameter 1
        param2: Description of parameter 2

    Returns:
        Description of return value

    Raises:
        ExceptionType: When this exception occurs
    """
```

### Class-Level Docstrings
```python
class ClassName:
    """
    Brief description of class purpose.

    Detailed explanation of responsibilities, usage patterns,
    and any important constraints.

    Attributes:
        attr1: Description
        attr2: Description
    """
```

## Essential Best Practices

- **Module docstrings**: All `.py` files should have module-level documentation
- **Type hints**: Use type hints on function signatures for clarity
- **Args/Returns**: Document parameters and return values for public functions
- **Inline comments**: Add comments only for complex logic that isn't self-evident
- **Examples**: Include usage examples in module headers when helpful
- **License**: Include "Author: TribanFT Project" and "License: GNU GPL v3" in headers

## Emoji Usage Policy

- **Do not use emojis** 

## YAML Documentation Standards

### Parser Pattern YAML Files

```yaml
# ═══════════════════════════════════════════════════════════════════════════
# Parser Name Pattern Definitions
# ═══════════════════════════════════════════════════════════════════════════
#
# Brief description of what this parser does.
#
# Author: TribanFT Project (or Your Name)
# License: GNU GPL v3
# Last Updated: YYYY-MM-DD
#
# ═══════════════════════════════════════════════════════════════════════════

metadata:
  name: parser_name
  version: 1.0.0
  author: TribanFT Project
  description: What this parser does
  enabled: true

# ═══════════════════════════════════════════════════════════════════════════
# Pattern Groups
# ═══════════════════════════════════════════════════════════════════════════

pattern_groups:
  # ┌─────────────────────────────────────────────────────────────────────┐
  # │ Pattern Group Name                                                   │
  # │ Description of what patterns in this group detect                    │
  # └─────────────────────────────────────────────────────────────────────┘
  group_name:
    - regex: '(?i)pattern'
      description: 'What this pattern matches'

# ═══════════════════════════════════════════════════════════════════════════
# Example Log Lines
# ═══════════════════════════════════════════════════════════════════════════
#
# 1. Example log line that matches pattern:
#    Log line here
#
# 2. Another example:
#    Another log line
#
# ═══════════════════════════════════════════════════════════════════════════
```

### Detector Rule YAML Files

Follow existing detector YAML format with header comments as shown in `rules/detectors/*.yaml`.

### YAML Best Practices

- **Header comments**: Include file purpose, author, license, and last updated date
- **Section dividers**: Use boxed comments (═══) for major sections
- **Group descriptions**: Add comments above each pattern group explaining its purpose
- **Example logs**: Always include example log lines that match patterns
- **Inline comments**: Add brief comments for complex patterns
- **Validation**: Test YAML syntax before committing: `python3 -c "import yaml; yaml.safe_load(open('file.yaml'))"`

## Quick Reference

**Validate docstrings:**
```bash
pip install pydocstyle
pydocstyle bruteforce_detector/
```

**Validate YAML:**
```bash
# Check all parser patterns
for f in bruteforce_detector/rules/parsers/*.yaml; do
  python3 -c "import yaml; yaml.safe_load(open('$f'))"
done

# Check all detector rules
for f in bruteforce_detector/rules/detectors/*.yaml; do
  python3 -c "import yaml; yaml.safe_load(open('$f'))"
done
```

**Follow standards:**
- PEP 257 (Docstring Conventions)
- Keep it concise and accurate
- Focus on "why" over "what" in comments
- **NEW**: YAML files must include header with author, license, date