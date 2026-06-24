---
name: dsl-proof-token
description: Why exploit-DSL proofs depend on the SENTINEL_INVARIANT_VIOLATED token in the assert message
metadata:
  type: project
---

The exploit DSL renders its invariant as `assertTrue(<cond>, "SENTINEL_INVARIANT_VIOLATED: ...")`
(`src/sentinel/tools/exploit_dsl.py::render_plan`). The result classifier
`_is_assertion_failure` / `_classify_validation_run` in `src/sentinel/tools/dynamic.py`
recognizes a genuine invariant violation by that token.

**Why:** forge prints a custom `assertTrue(cond, "msg")` failure as `[FAIL: msg]` WITHOUT the
literal "assertion failed". Before the token, sound DSL proofs (the assertion truly failed) were
misclassified as `validation_reverted_not_asserted` (a plain revert = not a proof), so
executed-proof recall was stuck at 0 even when glm-5.2 produced a working plan. The token appears
only in that one assertion's message, so a setup revert / broken mock (which prints a different
reason) can never trip it — keeping the oracle sound.

**How to apply:** if you change the DSL assertion message, keep the token (or update both sides).
A remaining open risk is *vacuous* breaks (assertion false because the attack did ~nothing, e.g.
22592-gas run) — the token makes the failure visible but does not prove the invariant was
meaningfully broken; rely on the counterevidence gate (executed proof must not auto-override it)
and inspect the persisted `exploit-dsl-render-*.t.sol` + before/after values. Related: [[never-commit]].
