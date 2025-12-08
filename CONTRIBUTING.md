# Contributing to TribanFT

Thank you for your interest in contributing to TribanFT! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and constructive
- Focus on what is best for the community
- Show empathy towards other contributors

## Getting Started

1. **Fork the repository**
2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/tribanft.git
   cd tribanft
   ```
3. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Guidelines

### Code Style

- Follow [PEP 8](https://pep8.org/) for Python code
- Use type hints for function parameters and returns
- Add docstrings to all modules, classes, and functions
- Keep functions focused and under 50 lines when possible

### Documentation

- Add module-level docstrings explaining purpose and usage
- Document all public functions with parameters and return values
- Include examples in docstrings for complex functionality
- Update README.md if adding new features

### Example Docstring Format

```python
def detect_threat(events: List[SecurityEvent], threshold: int) -> List[DetectionResult]:
    """
    Analyze security events and identify threats.
    
    Args:
        events: List of SecurityEvent objects to analyze
        threshold: Minimum number of events to trigger detection
        
    Returns:
        List of DetectionResult objects representing detected threats
        
    Example:
        >>> events = parser.parse_logs()
        >>> threats = detect_threat(events, threshold=20)
    """
    pass
```

### Testing

- Add unit tests for new functionality
- Ensure existing tests pass before submitting PR
- Test with real-world log samples when possible

## Submitting Changes

1. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add support for SSH log parsing"
   ```

2. **Use conventional commits**
   - `feat:` - New feature
   - `fix:` - Bug fix
   - `docs:` - Documentation changes
   - `refactor:` - Code refactoring
   - `test:` - Adding tests
   - `chore:` - Maintenance tasks

3. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Create Pull Request**
   - Provide clear description of changes
   - Reference related issues
   - Include test results if applicable

## Areas for Contribution

- **New log parsers** (SSH, FTP, Apache, Nginx)
- **Detection algorithms** (machine learning, anomaly detection)
- **Performance improvements** (optimization, caching)
- **Documentation** (tutorials, examples, translations)
- **Testing** (unit tests, integration tests)
- **Bug fixes** (see GitHub issues)

## Questions?

- Open an issue for discussion
- Check existing issues and PRs
- Review documentation in `/docs`

## License

By contributing, you agree that your contributions will be licensed under the GNU GPL v3 License.
