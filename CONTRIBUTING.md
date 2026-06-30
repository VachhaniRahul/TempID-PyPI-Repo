# Contributing to TempID

Thank you for your interest in contributing!

## Getting Started

```bash
git clone https://github.com/VachhaniRahul/TempID-PyPI-Repo.git
cd tempid
python -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"
```

## Running Tests

```bash
pytest -v
```

With coverage:
```bash
pytest --cov=tempid tests/ -v
```

## Code Style

This project uses `ruff` for linting and `mypy` for type checking:

```bash
pip install ruff mypy
ruff check tempid/
mypy tempid/
```

## Pull Requests

1. Fork the repository.
2. Create a branch: `git checkout -b feature/your-feature`.
3. Write tests for any new functionality.
4. Ensure `pytest` passes with no failures.
5. Submit a Pull Request with a clear description.

## Reporting Issues

Please open a GitHub Issue with:
- Python version
- `tempid` version (`pip show tempid`)
- Minimal reproducible example
