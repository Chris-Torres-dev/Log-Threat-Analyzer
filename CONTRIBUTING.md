# Contributing to Log Threat Analyzer

Thanks for your interest in contributing!

## Branching Strategy

| Branch | Purpose |
|---|---|
| `main` | Stable, production-ready code only |
| `dev` | Active development — all features merge here first |
| `feature/<name>` | Individual feature work |
| `hotfix/<name>` | Urgent bug fixes off `main` |

## Workflow

1. Branch off `dev` for new features:
   ```bash
   git checkout dev
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit clearly:
   ```bash
   git commit -m "feat: add brute-force detection to engine"
   ```

3. Open a PR into `dev`, not `main`

4. `main` is only updated via PR from `dev` when a version is stable

## Commit Message Format

Use this prefix convention:
- `feat:` — new feature
- `fix:` — bug fix
- `refactor:` — code restructure, no behavior change
- `docs:` — documentation update
- `test:` — adding or updating tests
- `chore:` — build/tooling/config changes

## Code Style

- **C++**: follow Google C++ Style Guide, use `clang-format`
- **Python**: follow PEP 8, use `black` for formatting
- **React/JSX**: use Prettier, functional components only
