# Policy test vectors

Fixture policies for the validation layers of `vigile-policy`.

| File | Expected outcome | Rejecting layer |
|---|---|---|
| `policy-valid-minimal.v0.json` | accepted | — |
| `policy-invalid-unknown-field.v0.json` | rejected | JSON Schema (`additionalProperties: false`, SEC-208) |
| `policy-invalid-missing-required.v0.json` | rejected | JSON Schema (`required`) |
| `policy-invalid-empty-groups.v0.json` | rejected | JSON Schema (`minItems: 1` — never an implicit "all") |
| `policy-invalid-bad-decision.v0.json` | rejected | JSON Schema (`enum`) |
| `policy-semantic-contradiction-interpreter.v0.json` | rejected | **compiler** (ISS-024, docs/POLICY_MODEL.md §3.3) — passes the schema by design |

Semantic vectors are fixtures for compiler-level contradiction tests: this
file denies an interpreter while allowing an application identity known to
require it, which only the semantic layer can detect.

Full JSON-Schema validation wired into `cargo test` lands with ISS-010;
CI currently checks JSON syntactic validity only.
