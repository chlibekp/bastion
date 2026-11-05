# Phase 2 Notes

Decisions made during execution, work deferred, and what later phases must pick up. Read the carry list before starting a later phase.

## Carry to later phases

- to T5: "\$host" keeps backslash after lexing; template must treat \$ as literal.
- to T4: wire scripts/check-directives-linked.sh build/release/bastion N into release verification.
- to Phase 5: re-test -T round-trip end to end once rewrite and return consume templates. A value with both ' and $ can't round-trip as text; the printer could pick a spelling per argument type from the schema.
- to Phase 3: set IPV6_V6ONLY on [::] listeners; make serve directory absolute before chdir or daemonise.
- to Phase 14: statement cap or byte budget on AST size, reload OOM-killing master is an outage. Errors echo env-expanded values (secrets) over the admin API.
- to Phase 6: duplicate listen flags (tls tls).
- to the phase adding the first BST_CFG_POST hook: extend scripts/check-directives-linked.sh to count the bst_cfg_post section.
- to the phase adding the first BST_CFG_POST hook: move duplicate hook-name check to the one-time registry build with a _with form and a unit test.
- Every task that adds a directive follows the guidance at the top of `src/config/compile.h` (also architecture.md) and runs `./dev make gen-reference`; `test_reference_up_to_date` fails otherwise.
- Phase 2 registers `user`, `workers`, `pid`, `error_log`, `server`, `listen`, `name`, `location`, `include`, `client_max_body_size`. Later phases extend these and never re-register them.
- Tests tagged `until_phase5` and `until_phase9` pin `root` and `proxy` as unknown; Phases 5 and 9 flip them, as listed in their plan amendments.
- `listen` takes one argument until a later phase raises `max_args` and adds flags as `BST_T_ENUM` values.

## Rulings

Each states what was decided, why, and what it costs if wrong.

- Ruling A: WORD keeps raw text; a directive's argspec decides whether an arg compiles as a template, so bare `$uri` works as config-language examples require — cost if wrong: argspec field.
- Ruling B: `${ENV}` expands inside one token, in WORD and double-quoted strings, never in single-quoted. An env value is literal: it can't create tokens or template variables, including a `;`, `}` or `$` in the value — stops config injection through env — cost if wrong: a user can't put template syntax in env.
- Ruling C: parser takes an option disabling include; fuzz_cfg uses it — fuzzer mustn't read host files — cost if wrong: none.
- Ruling D: named compile-time constants: include depth 16, block nesting 64, token 1 MiB, files per parse 1,048,576 (was 4096; raised by the Phase 2 final review, the 64 MiB byte cap is the real bound), total config bytes 64 MiB, each a clear error — plan requires bounded handling; these guard parsing itself, not an operator tunable — cost if wrong: raise a constant.
- Ruling E: section holds pointers to tables with `used`, not the tables, so ASan global redzones can't break iteration; `__start_`/`__stop_` weak so zero tables links — known ASan pitfall — cost if wrong: small macro change.
- Ruling F: T3 and T4 tests register test-only directives from the test file; Phase 5, 9 tasks register real ones, generic mechanisms proven with test tables — cost if wrong: none.
- Ruling G: defaults_applied uses `server { listen 8080; }`; `server {}` stays an error per no_listen — matches config-language simple example — cost if wrong: test wording.
- Ruling H: scope structs in src/config/compile.h, extended by later phases. Inheritance by struct copy: a child scope starts as a copy of its parent's inheritable part, then applies its own directives. All non-block directives at a level apply before descending into child blocks, so order within a block doesn't matter. Lists replace by pointer unless a directive appends. `bst_dir_apply` is `int (*)(bst_cfg_ctx *, const bst_ast_node *, bst_err *)` with ctx giving current scope and kind — simplest thing satisfying "child scalars replace"; every later phase depends on it, so architecture.md gets it — cost if wrong: refactor before many directives exist.
- Ruling I: `include` is registered for docs and contexts, with no-op apply since parser expanded it — cost if wrong: none.
- Ruling J: add `bst_str bst_tpl_eval_header(const bst_tpl *, const bst_var_ctx *, bst_arena *, bool *unsafe)` to Interfaces — test needs it, header injection defence — cost if wrong: signature.
- Ruling K: T6 parses `serve` and `proxy` args and generates the AST through compile. Until `root` and `proxy` register in Phases 5 and 9, compile reports unknown directive and exits 1; no test asserts success yet. Phases 5 and 9 must add end-to-end tests — cost if wrong: CLI edit then.
- Ruling L: -T identical means fixed point: `-T` output, re-parsed and printed by `-T`, is byte-identical — defined and testable — cost if wrong: test.
- Ruling: double-quoted unknown escapes are kept verbatim, reversing the implementer-dispatch rule "unknown escapes are ERROR"; config-language.md states it; \r added — matches nginx, user asked for nginx-like config, real regexes use "\.php$" — cost if wrong: a typo'd escape keeps its backslash rather than erroring.
- Ruling: only whitespace, ; { } or EOF may follow a closing quote — same as nginx, stops silent argument splits — cost if wrong: small lexer change.
- Ruling: delete bst_cfg_opts.base_dir, string parses resolve relative to name — no caller needs it, CLI serve and proxy use no includes — cost if wrong: one field back.
- Ruling: fixtures generated in temp dirs accepted instead of tests/fixtures/cfg/ — symlinks, FIFOs and thousands of files can't be checked in — cost if wrong: none.
- Ruling: rate suffix k is 1024, same as sizes — one rule across config, spec lists 1k/s beside 16k — cost if wrong: one constant, docs note.
- Ruling: schema gains any_name catch-all, subname (name, first arg), keywords on types, list flag, file-mode type, quoted options — needed to express the plan's example; about 100 tasks build on this — cost if wrong: small table fields.
- Ruling: bare word matching ^[a-z][a-z0-9_]*= not declared by the directive is an error; quoting keeps it positional — silent no-ops are banned, disk siz=50g would otherwise be a directory — cost if wrong: unusual values need quotes.
- Ruling: y = 365d added to durations — spec example uses expires 1y — cost if wrong: leap-year imprecision, harmless for cache lifetimes.
- Ruling: example changes sample=1.0 to sample=100% — avoids a float type, parsers have no floats — cost if wrong: one type added later.
- Ruling: leading zeros rejected for int, size, duration, rate, percent; mode= has its own octal type — 0600 read as decimal 600 is a permission bug — cost if wrong: an unusual config value errors clearly.
- Ruling: bst_dir_apply becomes int (*)(bst_cfg_ctx *, const bst_directive *, const bst_ast_node *, bst_err *), with bst_dir_pos, bst_dir_npos, bst_dir_opt, bst_dir_has_require — so about 100 tasks don't each reimplement arg classification — cost if wrong: signature change now is cheap.
- Ruling: apply is always required, no BST_TEST gate — forgotten .apply otherwise passes every test tier — cost if wrong: test tables need a no-op.
- Ruling: balance exclusivity flag (.subname_exclusive) and quoting hints in unknown-option and lexer messages folded into Task 4's dispatch, reviewed there — reviewer rated non-blocking, must land before real two-word directives, resuming a 250k-token implementer costs more — cost if wrong: Task 4 reviewer catches it.
- Ruling: nested locations added now, location valid in server and location with parent and children; Phase 5 plan amended to extend name and location — plan's Phase 5 requires it, cheap now — cost if wrong: unused fields.
- Ruling: bst_cfg_push renamed bst_cfg_push_owned; bst_cfg_list_append copies for inherited lists — makes sibling overwrite impossible — cost if wrong: O(n) per append at config time only.
- Ruling: distinct bst_header_tpl type, evaluator returns status and empty string unless OK; bst_tpl_eval_header removed — header injection impossible by construction, not by caller care — cost if wrong: small extra type.
- Ruling: header-unsafe bytes are all CTLs except HTAB, plus 0x7F, per RFC 9110; plain eval doesn't scan — differential-parsing hazard with VT, FF; removes hot-path scan — cost if wrong: an unusual value gets refused.
- Ruling: template schema hook installed now from bst_cfg_compile, reversing implementer's deferral — no real directive has a template arg yet so nothing breaks, and unknown variables can't slip through -t — cost if wrong: none.
- Ruling: -T prints a default once, at the scope where the directive first becomes valid, accepting the implementer's deviation from "every scope" — repeating defaults in children would override inherited values, and compile already works this way — cost if wrong: less explicit -T output.
- Ruling: --port 080 rejected, matching config's leading-zero rule — consistency — cost if wrong: none.
- Ruling: positionless errors (unopenable file) print path: message — a file that can't open has no line or column — cost if wrong: none.
- Ruling: singleton blocks synthesised when absent so their children's defaults apply — sandbox defaults would otherwise silently be off — cost if wrong: one flag per block.
- Ruling: lists replace on first statement in a scope through an owner tag; bst_cfg_list_extend for real appends; defaults always replaced — spec says lists replace — cost if wrong: an append directive picks extend explicitly.
- Ruling: post hooks take (bst_config *, bst_cfg_ctx *, bst_err *), registered by BST_CFG_POST in a linker section — fixes ASan use-after-free on error positions and lets hooks resolve references — cost if wrong: small API.
- Ruling: bst_cfg_warn collects positioned warnings, printed by -t and -T — spec requires warnings — cost if wrong: none.
- Ruling: control bytes other than tab rejected in string and path values; empty string rejected unless allowed; -T refuses them too — CWE-150 terminal injection from config or env — cost if wrong: a config with control bytes errors.
- Ruling: BST_CFG_MAX_FILES raised from 4096 to 1,048,576, 64 MiB bytes cap stays the real bound — one-file-per-vhost layouts at 10k vhosts — cost if wrong: none; supersedes the 4096 in preflight Ruling D.
- Ruling: listen max_args 1 until later phases add flags — schema stops advertising flags that fail — cost if wrong: none.
- Ruling: schema.c split into classifier, validation and registry, under the 800-line constraint — cost if wrong: file moves.
- Ruling: one residual task before merge, same as Phase 1 precedent — regresses a fixed Phase 1 finding, and a flag-typo guidance hole risks plaintext listeners in Phase 6 — cost if wrong: one more review.
- Ruling: tags and dtags unconditional in bst_cfg_common until a production list replaces them; BST_TEST removed from fuzz flags — tests and fuzz must run on the shipped layout — cost if wrong: 32 bytes per scope.
- Ruling: listen flags use BST_T_ENUM, guidance corrected — .keywords on a string type silently accepts typos — cost if wrong: none.
- Ruling: duplicate hook-name check stays in run_post_hooks for now, deviating from my "registry build" ruling, parked — works, Minor, no hook exists yet — cost if wrong: per-compile qsort, duplicate surfaces at compile not startup.

## Deferred minor findings

- Task 1: minor (deferred): lexer.c:126 redundant tail check, lexer.c:191 sticky check equivalent to done flag
- Task 1: minor (deferred): word_limit_exact third block comment wrong; test uses hook without BST_TEST guard; long comment in lexer.h
- Task 2: minor (deferred): no AST node cap, 64 MiB of a; uses about 1.4 GB under ASan (root-owned config, so low risk); bst_err.msg truncates long include chains; no literal ${ in WORD or STRING_TPL; source $$ stays two chars in text, state in parser.h; missing ; column for quoted last arg points at string start
- Task 2: minor (deferred): chain[] bound held by convention, add _Static_assert or explicit guard; ASSERT before rmdir_tmp leaks temp dir on failure including 70 MiB bytes_limit test, atexit fix; long lines over ColumnLimit 100
- Task 3: minor (deferred): suggestion ignores name length (foo suggests root); duplicate flags pass (listen 443 tls tls); size, duration, rate have no range; PATH accepts newline and tab, STRING accepts empty; BST_CTX_ALL undefined at 32 contexts; bst_parse_kv output unused; many_siblings_are_linear asserts no timing
- Task 3: minor (deferred): hand-listed deps for test_cfg_schema_empty link fail loudly on change; balance hash arg count message excludes subname; Levenshtein guard comment stale
- Task 4: minor (deferred): name duplicate scan O(names^2) bounded by 32 args per directive; listen error wording otherwise; *:80 and localhost:80 rejected, nginx convenience not required by spec
- Task 4: minor (deferred): cmp_lkey tie-break compares arena pointers across chunks, could name the wrong "first listen", use index; bst_cfg_common.tags test scaffolding in shipped struct, drop once a real list exists; no test at workers bound 4096/4097; bare-IP message unasserted; no committed global+location default fixture (ancestors mutant survives)
- Task 5: minor (deferred): registry collision check over-strict for exact name that's a prefix of a registered prefix (documented)
- Task 5: minor (deferred): schema tpl hook is a sticky global, tests call set_tpl_check(NULL); header-type misuse error depends on -Werror and an explicit cast defeats it
- Task 6: minor (deferred): escaping can push a value past the 1 MiB token limit with a misleading message; serve can't take a directory starting with -, -- unsupported; -c twice uses the last; -t -T acts as -T; tpl_len and len compares in dump untested directly (reparses is the real check)
- Task 6: minor (deferred): test_reference_failure_leaves_no_temp_file is vacuous (missing binary fails before .new is created), use a binary printing invalid JSON; missing default config and -c nope.conf print the path twice
- Final fix wave: minor (deferred): -T prints synthesised singletons and defaults after user blocks; absent singletons compile after explicit sibling blocks (cross-block reads belong in hooks, documented); BST_CFG_POST not in check-directives-linked.sh until first hook exists
- Residual: minor (deferred): 10k-vhost arena not re-measured after the layout change (estimate 9.5 MB, +64 B per scope); read_file streaming byte-cap paths untested; enum suggestion matches very short tokens to short values

## Final verification on b565501

`test-unit`, `test-unit BUILD=musltest`, `test-tsan`, `test-int` (66 passed, 1 skipped), `test-int BUILD=musltest` (57 passed, 10 skipped), `test-vm K=kernel_features` on `current` and `floor` (6 passed each), `test-deps`, `check-release BUILD=release`, `fuzz-smoke SECS=5` (7 harnesses), `tests/host/test_dev_paths.sh` and a clean `gen-reference` diff all pass. arm64 only.
