# Contributing to ReconForge

## Git workflow

1. Never commit directly to `main` (protected branch).
2. Create one branch per task: `feature/feature-name`, `fix/bug-name`, `docs/topic`.
3. Open a Pull Request as soon as work starts (as *draft* if unfinished) for mutual visibility.
4. CI (lint + tests) must pass before merging.
5. At least one review from the other collaborator is required before merging.
6. Merge with "Squash and merge" to keep a clean, readable `main` history.
7. Delete the branch after merging.

## Commit convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <short imperative description>

[optional body]
```

Types used: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `perf`, `style`.

Examples:
```
feat(scanner): add subdomain enumeration module
fix(cli): fix parsing of the --output option
docs(readme): update the installation section
```

## Code style

- Formatting: `black`
- Linting: `ruff`
- Typing: type annotations required on all public functions, checked with `mypy`
- Docstrings: Google style on all public functions/classes

Before every commit:
```bash
black src/ tests/
ruff check src/ tests/
mypy src/
pytest --cov=src
```

## Tests

Every new feature must come with unit tests in `tests/`.
Coverage target: 70%+ on business logic (excluding pure CLI parsing).

## Issues

Every roadmap task should go through an Issue before development, with the matching label
(`feature`, `bug`, `docs`, `enhancement`). The associated PR must reference the issue
(`Closes #12`).
