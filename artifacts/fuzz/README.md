# Local GNU Fuzz Runs

The default GNU/Linux fuzz campaign driver writes local run outputs under:

`artifacts/fuzz/runs/<timestamp>/`

That subtree is ignored by default because long fuzzing campaigns can produce
large local corpora, crash artifacts, and logs.

The reproducible runner is:

```bash
scripts/run_gnu_fuzz_campaign.sh --time 1800
```

Curated results that are intended to become part of the repository's research
artifacts should be copied out of a specific run and committed separately with
context, summaries, and interpretation notes.

Tracked checkpoint so far:

- `artifacts/fuzz/c1-gnu-asan-20260423.json`
- `artifacts/fuzz/c1-gnu-asan-20260423.md`
