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

Since 2026-06-25 a DSL plan only confirms when a **differential control** passes: the rendered test
is run twice — full (attack present) must FAIL with the token, and the CONTROL (`render_plan(...,
include_attack=False)`, attack removed) must PASS. If the control also fails, the break is *vacuous*
(assertion false regardless of the attack) and is rejected, not confirmed. Confirmation also requires
the attack to call the hypothesis's affected function (`attack_calls_hit_function`). Free-form PoCs
have no structured attack/control split, so a free-form assertion failure is `needs_review`, never
`executed_poc_confirmed`. Proof attribution is per-hypothesis: reporting reads `hypothesis.proof_status`
only, never the global batch `run_validation_artifacts` classification. Related: [[blind-eval]], [[never-commit]].
