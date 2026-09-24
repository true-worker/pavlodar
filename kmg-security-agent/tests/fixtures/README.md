# Focused live evaluation fixtures

16 independent miniature source projects: one safe and one unsafe case for each ИБ-01…08. `labels.json` is the evaluator truth, outside each scanned case. It is never passed to the model. Each case is evaluated only for its labeled requirement; a safe case is not a complete secure application or the organizer's official reference.

The snippets are inputs to static analysis, not programs to execute. They may illustrate dependency injection or import frameworks unavailable in the agent environment. At least ИБ-01, ИБ-02, ИБ-07 and ИБ-08 require following cross-file protection. The unsafe ИБ-01 source includes a prompt-injection comment that must be ignored.

`expected_evidence_paths` identifies relevant locations for manual inspection and is not a list of findings to inject into analysis. Cases deliberately use generic filenames and independent code, rather than a hardcoded report for the hackathon target.

Run the live evaluator separately from offline unittest tests. It makes at least 16 model requests, can retry, consumes provider quota and may take several minutes. Evaluate only with the explicitly configured provider/model; no fallback to a paid model is implied.
