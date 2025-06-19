# OpenADP Test Suite Structure

## Overview

The OpenADP test suite is organized to support scalable, maintainable, and CI-friendly testing. The structure is designed to separate unit, integration, and end-to-end (E2E) tests for clarity and reliability.

## Directory Layout

- **Unit tests** are placed next to the modules they test (e.g., `prototype/src/openadp/auth/test_keys.py` tests `keys.py`).
- `tests/integration/` — Integration tests for client-server flows, protocol interactions, and multi-component scenarios (to be expanded in Phase 3)
- `tests/e2e/` — End-to-end tests simulating real user scenarios (to be added in Phase 3+)
- `tests/auth/`, `tests/server/` — Legacy test locations (will be merged or removed as part of migration)

## Running Unit Tests

From the project root:

```bash
pytest --cov=prototype --maxfail=3 --disable-warnings -v
```

Pytest will automatically discover all `test_*.py` files, including those next to modules in the source tree.

## Migration Plan

- Only true unit tests are next to their modules for now.
- Integration and E2E tests will be added in later phases.
- Legacy test scripts and ad-hoc tests will be refactored and migrated incrementally.

## Continuous Integration

- All tests are intended to be run in CI on every commit/PR.
- Coverage reports will be monitored to ensure high reliability.

## See Also
- [../docs/test-plan.md](../docs/test-plan.md) for the overall test strategy and phased plan. 