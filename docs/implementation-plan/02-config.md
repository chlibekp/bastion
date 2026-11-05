# Phase 2: Configuration

**Goal:** Parse the config language in [config-language.md](config-language.md) into an immutable compiled config, with precise errors and a schema that generates the docs.

**Architecture:** Text → tokens → AST → schema validation → compiled `bst_config`. The compiled config is immutable, built in master, and inherited by workers. A failed compile leaves the running config untouched.

**Spec:** [config-language.md](config-language.md), [README.md](README.md).

## Review Focus

1. Include cycles and glob expansion to thousands of files → clear error or bounded handling, no hang. (Task 2)
2. Config with CRLF endings, a UTF-8 BOM, or no final newline → parses identically to the LF version. (Task 1)
3. Compile failure partway through → frees everything and returns an error, which matters since reload relies on it. (Task 4)
4. Directive set in `location` but valid only in `server` → error naming the valid contexts. (Task 3)
5. Duration or size overflow, such as `99999999999g` → error instead of wrapped value. (Task 3)

---

### Task 1: Lexer

**Files:**
- Create: `src/config/lexer.{c,h}`
- Test: `tests/unit/test_cfg_lexer.c`, `fuzz/fuzz_cfg.c`

**Interfaces:**
- Produces: `bst_lexer_init(bst_lexer *, bst_arena *, const char *text, size_t len, const char *file)` (the arena holds decoded double-quoted strings), `bst_token bst_lexer_next(bst_lexer *)`. Token kinds: `WORD`, `STRING_RAW`, `STRING_TPL`, `SEMI`, `LBRACE`, `RBRACE`, `EOF`, `ERROR`. Each token has file, line and col.

- [ ] **Step 1: Write failing tests**
  - `basic_statement`: `listen 80;` → WORD WORD SEMI EOF, with correct columns.
  - `comments_and_quotes`: `"a#b" # c` → single string `a#b`.
  - `escapes`: `"\n\t\"\\"` decoded; `'\n'` left raw.
  - `unterminated`: `"abc` → ERROR with the opening line and column.
  - `bom_crlf`: BOM plus CRLF gives the same tokens and line numbers as LF.
  - `nul_byte`: embedded NUL → ERROR, never truncation.
- [ ] **Step 2: Run** `./dev make test-unit T=cfg_lexer` → FAIL.
- [ ] **Step 3: Implement** in a single pass over bytes, with no recursion and a token length limit of 1 MiB.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(config): add lexer`

### Task 2: Parser, includes and environment expansion

**Files:**
- Create: `src/config/parser.{c,h}`
- Test: `tests/unit/test_cfg_parser.c`, fixtures in `tests/fixtures/cfg/`

**Interfaces:**
- Consumes: lexer.
- Produces: `bst_ast *bst_cfg_parse_file(const char *path, bst_arena *, bst_err *)` and `bst_cfg_parse_string`. `bst_ast_node { name, args[], nargs, children, loc }`.

- [ ] **Step 1: Write failing tests**
  - `nested_blocks`: server → location tree shape.
  - `missing_semicolon`: reports at the line where the semicolon was expected.
  - `unbalanced_brace`: reports position of the unclosed block's opening.
  - `include_glob_sorted`: `b.conf`, `a.conf` are merged in sorted order.
  - `include_relative`: resolved against the including file.
  - `include_cycle`: A includes B includes A → error listing the chain.
  - `include_depth`: depth 17 → error.
  - `env_default`: `${X:-y}` with X unset → `y`.
  - `env_missing`: `${X}` with X unset → error naming X.
  - `depth_limit`: 1000 nested blocks → error with no stack overflow.
- [ ] **Step 2: Run** `./dev make test-unit T=cfg_parser` → FAIL.
- [ ] **Step 3: Implement** an iterative parser with an explicit stack.
- [ ] **Step 4: Run** same → PASS. Also `./dev make fuzz T=fuzz_cfg SECS=60` → no crash.
- [ ] **Step 5: Commit** `feat(config): add parser with includes and env expansion`

### Task 3: Schema and value types

**Files:**
- Create: `src/config/schema.{c,h}`, `src/config/values.{c,h}`
- Test: `tests/unit/test_cfg_schema.c`

**Interfaces:**
- Consumes: `bst_ast`.
- Produces: `bst_directive` (see config-language.md), `BST_DIRECTIVES(table)` registration through a linker section so subsystems self-register. `BST_CTX_{GLOBAL,SERVER,LOCATION,UPSTREAM,...}`. Value parsers: `bst_parse_size`, `bst_parse_duration_us`, `bst_parse_rate`, `bst_parse_bool`, `bst_parse_enum`, `bst_parse_kv(arg, "key=", ...)`. `bst_cfg_validate(ast, bst_err *)`.

- [ ] **Step 1: Write failing tests**
  - `size_values`: `16k`=16384, `2g`, `512`; `1x`, `-1`, `99999999999g` → error.
  - `duration_values`: `50us`, `10ms`, `30s`, `1d`; `5` with no unit → error.
  - `rate_values`: `100/s`, `6000/m`=100/s, `1k/s`; `0/s` → error.
  - `unknown_directive_suggestion`: `proxi` → message contains `did you mean "proxy"`.
  - `wrong_context`: `root` under `upstream` → message lists valid contexts.
  - `duplicate_scalar`: two `root` at one level → error with both locations.
  - `all_directives_documented`: walk the table; each `doc` is non-empty and each default parses under its own argspec.
- [ ] **Step 2: Run** `./dev make test-unit T=cfg_schema` → FAIL.
- [ ] **Step 3: Implement.** Suggestions use bounded Levenshtein distance, at most 2.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(config): add directive schema and value types`

### Task 4: Compile and inheritance

**Files:**
- Create: `src/config/compile.{c,h}`, `src/config/core_directives.c`
- Test: `tests/unit/test_cfg_compile.c`

**Interfaces:**
- Produces: `bst_config *bst_cfg_compile(const bst_ast *, bst_err *)`, `void bst_config_free(bst_config *)`. Scope structs: `bst_cfg_global`, `bst_cfg_server`, `bst_cfg_location`. Merge is `global → server → location`. `tls auto` implied listener expansion goes here and is added by Phase 14. Core directives at this stage: `user`, `workers`, `pid`, `error_log`, `server`, `listen`, `name`, `location`, `include`.

- [ ] **Step 1: Write failing tests**
  - `inherit_scalar`: `client_max_body_size` at server is inherited by a location that omits it.
  - `child_overrides`: value in location wins.
  - `defaults_applied`: empty server compiles and has documented defaults.
  - `no_listen`: `server {}` with no listen and no `tls auto` → error with a helpful message.
  - `duplicate_listener_name`: same address, port and name in two servers → error.
  - `compile_failure_no_leak`: invalid config compiled under ASan and LeakSanitizer reports no leak.
- [ ] **Step 2: Run** `./dev make test-unit T=cfg_compile` → FAIL.
- [ ] **Step 3: Implement** with all compiled data in a single arena, so freeing is a single call.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(config): compile AST into scoped runtime config`

### Task 5: Compiled templates

**Files:**
- Create: `src/config/template.{c,h}`
- Test: `tests/unit/test_cfg_template.c`

**Interfaces:**
- Produces: `bst_tpl *bst_tpl_compile(bst_str, bst_arena *, bst_err *)`, `bst_var_register(name, bst_var_fn)` and prefix variables (`arg_`, `http_`, `cookie_`), `bst_str bst_tpl_eval(const bst_tpl *, const bst_var_ctx *, bst_arena *)`, `bst_header_tpl *bst_tpl_compile_header(bst_str, bst_arena *, bst_err *)` (a distinct type for every header value; literal CR, LF, NUL, other control bytes except HTAB and 0x7F are a compile error) with `int bst_header_tpl_eval(const bst_header_tpl *, const bst_var_ctx *, bst_arena *, bst_str *out)` returning `BST_TPL_OK`, `BST_TPL_UNSAFE` or `BST_TPL_FAIL` (`*out` is empty unless OK), and the `bst_schema_set_tpl_check` hook, installed by `bst_cfg_compile`, so `-t` compile-checks `BST_T_TEMPLATE` args.

- [ ] **Step 1: Write failing tests**
  - `literal_only`: evaluates without allocating.
  - `mixed`: `/new/$1?x=$arg_y` substitutes.
  - `unknown_var`: `$nosuch` → compile error with position.
  - `escape_dollar`: `$$` is a literal `$`.
  - `missing_value`: undefined `$arg_y` → empty string.
  - `crlf_in_value`: a variable expanding to text containing CR or LF is flagged by `bst_tpl_eval_header`, so header injection is impossible.
- [ ] **Step 2: Run** `./dev make test-unit T=cfg_template` → FAIL.
- [ ] **Step 3: Implement** templates as a flat array of literal and variable ops.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(config): add compiled variable templates`

### Task 6: Command line

**Files:**
- Create: `src/config/cli.{c,h}`, `scripts/gen-config-reference.sh`, `docs/config-reference.md` (generated)
- Modify: `src/main.c`
- Test: `tests/integration/test_cli.py`

**Interfaces:**
- Produces: `bastion [-c file] [-t] [-T] [--version]`, `bastion serve <dir> [--port n]`, `bastion proxy <url> [--port n]`, `bastion --dump-schema`. Default config path `/etc/bastion/bastion.conf`. `serve` and `proxy` generate an AST in memory and run through the same compile path. Exit codes: 0 ok, 1 config error, 2 usage.

- [ ] **Step 1: Write failing tests**
  - `test_t_ok`: `-t` on a valid file prints `configuration ok` and exits 0.
  - `test_t_error`: `-t` on an invalid file exits 1 and prints `file:line:col`.
  - `test_T_effective`: `-T` prints defaults, and its output parses and compiles again to an identical result.
  - `test_reference_up_to_date`: regenerating the reference gives no diff against the committed file.
- [ ] **Step 2: Run** `./dev make test-int K=cli` → FAIL.
- [ ] **Step 3: Implement.** Only option parsing and dispatch live here.
- [ ] **Step 4: Run** same → PASS.
- [ ] **Step 5: Commit** `feat(config): add CLI, config test and generated reference`
