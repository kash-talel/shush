# Issue Routing Summary

Show every open issue with its runner, model and merge policy.

Run `powershell -NoProfile -File .claude/scripts/route-issue.ps1 -List` and print its output
verbatim. Routing is computed live from labels and titles (`.claude/scripts/Policy.ps1`); to
pin an issue, add the label `route:opus`, `route:claude` or `review-required` on GitHub.
Do not change anything.
