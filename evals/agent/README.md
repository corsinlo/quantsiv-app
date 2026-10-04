# Agent eval harness (WP10)

Measures one thing: does a coding assistant produce fewer policy-blocked cryptographic changes
when it has the Quantsiv policy MCP server than without it? It records **gate verdicts only**,
from the same `policy.evaluate` function the merge gate uses. No model is called from here.

## How a run works

1. Pick a task from `tasks.yml` (a repository and an instruction for the assistant).
2. Check the repository out twice: `before/` (the base commit) and `after/` (the assistant's
   result). Produce `after/` by running the assistant yourself, once **without** the MCP server
   and once **with** it (`python -m quantsiv_scanner mcp --repo .` configured in the assistant).
3. Record the verdict:

   ```text
   python evals/agent/run.py --task <id> --assistant <name> --with-mcp|--without-mcp \
       --before before/ --after after/
   ```

   This scans both trees with the rules engine, diffs the assets, evaluates the delta under the
   task repository's `quantsiv.yml`, and appends one line to `evals/agent/results.jsonl`.

## Rules

- Results are not committed until a report is written from them, and **no benefit is quoted
  before it is measured**. Today there are no results.
- Tasks run on public demo repositories only. The repository list in `tasks.yml` is empty until
  the demo repositories exist; the sample task uses this repo's own fixture so the harness can
  be exercised.
