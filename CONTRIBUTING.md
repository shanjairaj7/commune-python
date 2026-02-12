# Contributing to Commune Python SDK

Thanks for your interest in contributing! Here's how to get started.

## Setup

```bash
# Clone the repo
git clone https://github.com/shanjairaj7/commune-python.git
cd commune-python

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in development mode
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v
```

Tests use `httpx.MockTransport` — no network calls or API keys needed.

## Code Style

- Type hints on all public functions and methods.
- Docstrings on all public classes and methods (Google style).
- Keep `from __future__ import annotations` at the top of every module.
- Run `python3 -m py_compile commune/*.py` to check for syntax errors.

## Adding a New Resource

If the Commune API adds a new resource (e.g. `/v1/contacts`):

1. Add Pydantic models to `commune/types.py`.
2. Add a `_Contacts` class to `commune/client.py` (sync) and `commune/async_client.py` (async).
3. Wire it into `CommuneClient.__init__` and `AsyncCommuneClient.__init__`.
4. Export new types from `commune/__init__.py`.
5. Add tests in `tests/`.
6. Update `README.md` and `API_REFERENCE.md`.

## Pull Requests

- One feature or fix per PR.
- Include tests for new functionality.
- Update `CHANGELOG.md` under an `[Unreleased]` section.
- Keep commits focused and descriptive.

## Reporting Issues

Open an issue on GitHub with:
- Python version (`python3 --version`)
- SDK version (`pip show commune-mail`)
- Minimal reproduction code
- Full traceback

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
