# Conformance fixture format

Each fixture is a JSON file. Naming convention:
`<spec>_<scenario>_<expected-outcome>.json`. Examples:
`rfc9112_request_line_with_lf_only_reject.json`,
`rfc9112_chunked_with_empty_extension_accept.json`.

## Schema

```
{
  "name":           String,     // human-readable id
  "spec":           String,     // RFC anchor
  "input_hex":      String,     // space-separated hex pairs
  "expect":         "accept" | "reject",
  "expect_reason":  String,     // why this outcome is correct
  "leniency":       Object,     // optional H1LeniencyConfig fields
  "expected_method": String,    // present when expect == "accept"
  "expected_uri":    String,
  "expected_version": String
}
```

- `input_hex` is a flat string of 2-character hex pairs separated by
  ASCII space. Whitespace between pairs is collapsed during loading.
  Comments inside the hex string are not supported; the JSON `name`
  field is the place for human notes.
- `leniency` is keyed by `H1LeniencyConfig` field name. Any omitted
  field uses the strict default (`False`). The conformance runner
  hands the resulting config to the parser before applying the input
  bytes.
- `expected_method` / `expected_uri` / `expected_version` are required
  only when `expect == "accept"` and the fixture is a request-line
  test. Header / body fixtures will grow `expected_headers` /
  `expected_body` fields when those parsers gain conformance
  coverage.

## Adding fixtures

1. Pick the RFC section the scenario tests.
2. Capture the wire bytes (e.g. via tcpdump, or hand-author from the
   ABNF grammar in the RFC).
3. Convert to space-separated hex with `xxd -p -c 1 | tr '\n' ' '`.
4. Drop the JSON in the appropriate `conformance/<area>/` subdir.
5. Re-run the conformance runner (`pixi run test-conformance-h1`).
6. If the fixture is sensitive to a leniency flag, document the flag
   under `leniency`.

The runner loads every `*.json` in `conformance/h1/` automatically;
new fixtures need no test-code change.
