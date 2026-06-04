# Contributing to dockersec

Thank you for helping make Docker security more accessible.
Here is everything you need to contribute.

---

## Ways to Contribute

- Add a new YAML rule (no Go knowledge required)
- Improve an existing rule's description or fix
- Report a false positive or missed vulnerability
- Improve documentation
- Fix a bug or add a feature in Go

---

## Adding a Rule Without Writing Go

dockersec supports community rules written in YAML.
You do not need to know Go to add a rule.

### Rule File Location

- Dockerfile rules: `rules/dockerfile/`
- docker-compose rules: `rules/compose/`

### Dockerfile Rule Format

```yaml
id: DF021
type: dockerfile
severity: HIGH
description: |
  Explain what this instruction does wrong.
  Explain why it is a security or reliability problem.
  Write this for someone new to Docker.
fix: |
  Explain exactly how to fix it.
  Include a code example where possible.
match:
  instruction: RUN
  contains: "your pattern here"
```

### docker-compose Rule Format

```yaml
id: DC009
type: compose
severity: MEDIUM
description: |
  Explain the problem clearly.
fix: |
  Explain the fix with an example.
match:
  field: restart
  equals: "always"
```

### Severity Guide

| Severity | When to use |
|---|---|
| CRITICAL | Direct path to host compromise or secret exposure |
| HIGH | Serious security misconfiguration |
| MEDIUM | Bad practice that increases risk or attack surface |
| LOW | Hygiene issue that affects reliability or image size |

### Rule ID Naming

- Dockerfile rules: `DF` + next available number (check existing rules first)
- Compose rules: `DC` + next available number
- Custom/community rules: `CX` + descriptive suffix e.g. `CX_NODEJS_001`

---

## Submitting a Pull Request

1. Fork the repository
2. Create a branch: `git checkout -b feat/your-rule-name`
3. Add your rule file in the correct directory
4. Test it against a real Dockerfile or docker-compose.yml
5. Commit with a conventional commit message:
   `git commit -m "feat: add rule DF021 for xyz"`
6. Push and open a PR against the `dev` branch, not `main`

### PR Checklist

- [ ] Rule file is in the correct directory
- [ ] Rule ID does not conflict with an existing one
- [ ] Description explains the problem clearly for a Docker beginner
- [ ] Fix includes a concrete code example
- [ ] Tested against a real file that triggers the rule
- [ ] Commit message follows conventional commits format

---

## Reporting a Bug or False Positive

Open an issue with:
- Your Dockerfile or docker-compose.yml snippet
- The rule that fired (or did not fire)
- What you expected vs what happened

---

## Go Contributions

If you want to contribute Go code:

- Run `go build ./...` before submitting
- Follow the existing package structure
- Keep rule logic in `internal/rules/dockerfile/` or `internal/rules/compose/`
- One rule per file, named after the rule ID
- Open an issue first for large changes so we can discuss direction

---

## Branch Strategy

| Branch | Purpose |
|---|---|
| `main` | Stable releases only |
| `dev` | Integration branch, all PRs target this |
| `feature/xxx` | Your work branch |