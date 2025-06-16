# OpenADP Testing Guide

This document explains the testing infrastructure and CI/CD setup for OpenADP.

## Test Architecture

### 🧪 Test Categories

| Category | Description | When to Run | Location |
|----------|-------------|-------------|----------|
| **Unit Tests** | Core functionality, crypto, database | Every commit | `tests/unit/` |
| **Auth Tests** | Authentication & security | Every commit | `tests/auth/` |
| **Integration Tests** | Local server integration | Every commit | `tests/integration/` |
| **Manual Tests** | Production server tests | Manual only | Various (marked `@pytest.mark.manual`) |
| **E2E Tests** | Complex end-to-end workflows | Manual only | `tests/e2e/` |

### 🎯 Test Execution Strategy

**Automated (CI/CD)**:
- ✅ Unit Tests (258 tests)
- ✅ Authentication Tests (23 tests)  
- ✅ Integration Tests (19 tests)
- ✅ Co-located Tests (23 tests)

**Manual Only**:
- 🔧 Production Tests (10 deselected)
- 🔧 E2E Tests (10 deselected)

## Running Tests

### Local Development

```bash
# Run all automated tests
python run_tests.py

# Run specific test categories
python run_tests.py --unit-only
python run_tests.py --auth-only
python run_tests.py --integration-only

# Run manual tests (requires production setup)
python -m pytest -m manual

# Run with verbose output
python run_tests.py --verbose

# Run with coverage
python run_tests.py --coverage
```

### GitHub Actions (Automated)

Tests run automatically on:
- ✅ Every push to `main` or `develop`
- ✅ Every pull request
- ✅ Multiple Python versions (3.11, 3.12)

View results at: `https://github.com/your-username/openadp/actions`

## CI/CD Pipeline

### 🚀 GitHub Actions Workflow

The pipeline includes three parallel jobs:

#### 1. **Test Job** (`test`)
- Runs on Python 3.11 and 3.12
- Executes all automated test categories
- Verifies project structure and imports
- Generates test reports

#### 2. **Lint Job** (`lint`)
- Code formatting check (Black)
- Import sorting check (isort)
- Code quality analysis (Flake8)

#### 3. **Security Job** (`security`)
- Security vulnerability scanning (Bandit)
- Dependency vulnerability check (Safety)

### 🛡️ Branch Protection

When properly configured, the `main` branch requires:
- ✅ All tests must pass
- ✅ Code review approval
- ✅ Up-to-date with base branch
- ✅ No direct pushes allowed

## Test Configuration

### Pytest Configuration (`pytest.ini`)

```ini
[pytest]
markers =
    manual: marks tests as requiring manual interaction (deselected by default)

# By default, skip manual tests
addopts = -m "not manual"
```

### Manual Test Categories

Tests marked with `@pytest.mark.manual` include:
- Production server connectivity tests
- Real Keycloak authentication flows
- Complex multi-server setups
- Browser-based OAuth flows

## Optional Git Hooks

For additional local protection, install git hooks:

```bash
# Install optional pre-commit/pre-push hooks
./scripts/install-git-hooks.sh
```

This adds:
- **Pre-commit**: Runs unit tests before each commit
- **Pre-push**: Runs full test suite before each push

## Test Results Interpretation

### ✅ Success Indicators
```
🎉 ALL TESTS PASSED! Project status: GREEN ✅
Total: 6 test suites
Passed: 6
Failed: 0
Success Rate: 100.0%
```

### ❌ Failure Indicators
```
💥 X test suite(s) failed. Project status: RED ❌
```

### ℹ️ Deselected Tests
```
collected 29 items / 10 deselected / 19 selected
```
This is normal - manual tests are automatically skipped in CI.

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure you're in the project root and virtual environment is activated
2. **Path Issues**: Check that `PYTHONPATH` includes the project root
3. **Database Warnings**: SQLite threading warnings are expected in concurrent tests
4. **Manual Test Failures**: These require production server setup

### Debug Commands

```bash
# Check project structure
python -c "import openadp; print('OpenADP imported successfully')"

# Verify test discovery
python -m pytest --collect-only tests/unit/

# Run single test file
python -m pytest tests/unit/test_crypto_comprehensive.py -v

# Run with maximum verbosity
python -m pytest tests/unit/ -vvv
```

## Contributing

When contributing code:

1. ✅ Ensure all automated tests pass locally
2. ✅ Add tests for new functionality
3. ✅ Mark production-dependent tests as `@pytest.mark.manual`
4. ✅ Update this documentation if adding new test categories

## Performance

**Typical Test Execution Times**:
- Unit Tests: ~21 seconds
- Auth Tests: ~0.1 seconds  
- Integration Tests: ~14 seconds
- Full Suite: ~36 seconds

**GitHub Actions**: ~2-3 minutes total (parallel execution) 