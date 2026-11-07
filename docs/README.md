# shush documentation

Everything that defines, explains or verifies shush lives here. Start with the document that matches
what you need.

| You want to… | Read |
|---|---|
| Know what's done, what's next and which decisions were made | [`ROADMAP.md`](ROADMAP.md) |
| Implement or audit the on-disk format (vault, backup, attachments) | [`FORMAT.md`](FORMAT.md) |
| Understand the original product requirements | [`spec/master-specification.md`](spec/master-specification.md) |
| Understand the threat model and auth design | [`spec/security-model.md`](spec/security-model.md) |
| See the original architecture proposal | [`spec/architecture-plan.md`](spec/architecture-plan.md) |
| Run or extend the end-to-end tests | [`testing/README.md`](testing/README.md) |
| Report a vulnerability | [`../SECURITY.md`](../SECURITY.md) |

## How the documents relate

```
spec/                 the original blueprint (product + security requirements)
   │  reviewed adversarially → GitHub issues #1–#27 (labelled spec-review)
   ▼
ROADMAP.md            phases, status, PR links, owner decisions that amend the spec
FORMAT.md             the normative byte format actually implemented
testing/              per-phase end-to-end scripts + screenshots proving each phase
```

**Where the spec and the code disagree, the code follows `FORMAT.md` and the owner decisions in
`ROADMAP.md`.** Each deviation has a reason recorded in an issue. Examples: Argon2id takes the
keyfile hash as its secret input (#3), the whole header is authenticated (#1), imports never promote
an untrusted password (#19), and the Quick search hotkey is `Ctrl+Alt+Space` (#14).

## Conventions

- The spec documents in `spec/` are kept as written (historical record). Corrections go in issues,
  `ROADMAP.md` and `FORMAT.md`, not by silently editing the spec.
- Every phase PR adds its end-to-end script and at least one screenshot under `testing/phaseN/`.
- Security claims in the top-level README must be backed by a test or marked *planned*.
