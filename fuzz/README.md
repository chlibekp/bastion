# Fuzzing

Every parser has a libFuzzer harness `fuzz/fuzz_<name>.c` (ASan + UBSan) and a
hand-curated seed corpus in `fuzz/corpus/<name>/`.

Each run prints `== <name>: seed=N`; replay with `SEED=N`. Run one harness (`cfg` or `fuzz_cfg`) for n seconds, or all of them (default 60s each):

    ./dev make fuzz T=json SECS=30
    ./dev make fuzz-smoke [SECS=n]

Runs use a scratch copy of the corpus that is deleted afterwards; the checked-in corpus
is never changed. A crash, timeout or sanitizer report writes a reproducer to
`fuzz/crashes/` (git-ignored) and the run exits non-zero after the remaining harnesses
finish. Replay one with `build/fuzz/bin/fuzz_<name> fuzz/crashes/<file>`.

Add a harness: create `fuzz/fuzz_<name>.c` defining `LLVMFuzzerTestOneInput` and
`fuzz/corpus/<name>/` with a few seeds. It is picked up automatically. Per-harness
`-max_len` lives in `scripts/fuzz-smoke.sh` (default 4096).

Promote a fixed crash: fix the bug, confirm the reproducer no longer fails, then copy it
into `fuzz/corpus/<name>/` under a descriptive name and commit it as a regression.
