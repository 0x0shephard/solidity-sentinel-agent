---
name: never-commit
description: The user commits/pushes manually — never run git commit or push
metadata:
  type: feedback
---

Never run `git commit`, `git push`, or otherwise create commits in this repo. The user does all
committing themselves.

**Why:** explicit, repeated instruction — "do not commit anything, i will do it myself."
**How to apply:** make and verify edits, run tests, leave changes in the working tree, and report
what changed; stop short of committing unless the user explicitly asks in the moment.
