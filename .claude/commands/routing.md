# Issue Routing Summary

Show every open issue with its assigned model and runner.

## Steps
1. Load the open issues:
   ```powershell
   gh issue list --state open --limit 200 --json number,title,labels
   ```
2. For each open issue that is missing from `.claude/issue-routing.json`, classify and save it:
   ```powershell
   powershell -NoProfile -File .claude/scripts/route-issue.ps1 -Number <NUMBER>
   ```
   Do not reclassify issues already in the file.
3. Read `.claude/issue-routing.json` and join it to the open-issue list. Ignore entries for closed issues.
4. Print one markdown table, sorted by severity (critical, high, medium, low) and then by issue number:

   | # | Title | Model | Runner |
   |---|-------|-------|--------|

   - Model is the `model` field and runner is the `runner` field.
   - Shorten titles to about 70 characters.
   - Under the table, print counts per runner (for example `agy: 14 · claude: 20`).
   - Do not change any issue or file other than the routing file.
