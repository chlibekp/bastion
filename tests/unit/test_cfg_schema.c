#include "cfg_fixture.h"
#include "config/dump.h"
#include "config/parser.h"
#include "config/schema.h"
#include "config/values.h"
#include "core/arena.h"
#include "tap.h"

#include <stdint.h>
#include <string.h>

#define S(lit) ((bst_str){ (lit), (uint32_t)(sizeof(lit) - 1) })

/* ---- Helpers ---- */

static bst_arena *A;
static bst_err E;
static bst_schema *SC;
static bst_ast *AST;

static void schema_init(void) __attribute__((constructor));
static void schema_init(void)
{
	bst_err e;
	SC = bst_schema_build((const bst_dirtab *const[]){ &fx_tab }, 1, &e);
	if (!SC) {
		fprintf(stderr, "fixture schema: %s\n", e.msg);
		abort();
	}
}

static bst_ast *parse(const char *text)
{
	if (A)
		bst_arena_free(A);
	A = bst_arena_new(1 << 16);
	memset(&E, 0, sizeof E);
	return bst_cfg_parse_string(text, strlen(text), "t.conf", NULL, A, &E);
}

static int validate(const char *text)
{
	bst_ast *ast = AST = parse(text);
	if (!ast) {
		snprintf(E.msg, sizeof E.msg, "PARSE FAILED");
		return -2;
	}
	return bst_cfg_validate_with(SC, ast, &E);
}

static int has(const char *needle)
{
	return strstr(E.msg, needle) != NULL;
}

/* ---- Values ---- */

TEST(size_values)
{
	uint64_t v;
	ASSERT(bst_parse_size(S("512"), &v) && v == 512);
	ASSERT(bst_parse_size(S("16k"), &v) && v == 16384);
	ASSERT(bst_parse_size(S("1m"), &v) && v == 1048576);
	ASSERT(bst_parse_size(S("2g"), &v) && v == 2147483648ull);
	ASSERT(bst_parse_size(S("0"), &v) && v == 0);
	ASSERT(bst_parse_size(S("18446744073709551615"), &v) && v == UINT64_MAX);
	ASSERT(!bst_parse_size(S("18446744073709551616"), &v));
	ASSERT(!bst_parse_size(S("99999999999g"), &v));
	ASSERT(!bst_parse_size(S("17179869184g"), &v)); /* 2^34 * 2^30 = 2^64 */
	ASSERT(bst_parse_size(S("17179869183g"), &v));
	ASSERT(!bst_parse_size(S("1x"), &v));
	ASSERT(!bst_parse_size(S("-1"), &v));
	ASSERT(!bst_parse_size(S("+1"), &v));
	ASSERT(!bst_parse_size(S("1K"), &v)); /* case-sensitive */
	ASSERT(!bst_parse_size(S("1G"), &v));
	ASSERT(!bst_parse_size(S("1kb"), &v));
	ASSERT(!bst_parse_size(S("k"), &v));
	ASSERT(!bst_parse_size(S(""), &v));
	ASSERT(!bst_parse_size(S(" 1"), &v));
	ASSERT(!bst_parse_size(S("1 "), &v));
	ASSERT(!bst_parse_size(S("1.5k"), &v));
	ASSERT(!bst_parse_size(S("0x10"), &v));
	ASSERT(!bst_parse_size((bst_str){ "1\0" "k", 3 }, &v));
	/* Leading zeros are errors everywhere a number is read. */
	ASSERT(!bst_parse_size(S("00016k"), &v));
	ASSERT(!bst_parse_size(S("01"), &v));
	ASSERT(!bst_parse_size(S("007"), &v));
	ASSERT(bst_parse_size(S("0k"), &v) && v == 0);
}

TEST(duration_values)
{
	uint64_t v;
	ASSERT(bst_parse_duration_us(S("50us"), &v) && v == 50);
	ASSERT(bst_parse_duration_us(S("10ms"), &v) && v == 10000);
	ASSERT(bst_parse_duration_us(S("30s"), &v) && v == 30000000ull);
	ASSERT(bst_parse_duration_us(S("5m"), &v) && v == 300000000ull);
	ASSERT(bst_parse_duration_us(S("1h"), &v) && v == 3600000000ull);
	ASSERT(bst_parse_duration_us(S("1d"), &v) && v == 86400000000ull);
	ASSERT(bst_parse_duration_us(S("0s"), &v) && v == 0);
	ASSERT(!bst_parse_duration_us(S("5"), &v));
	ASSERT(!bst_parse_duration_us(S("s"), &v));
	ASSERT(!bst_parse_duration_us(S("5S"), &v));
	ASSERT(bst_parse_duration_us(S("1y"), &v) && v == 365ull * 86400000000ull);
	ASSERT(!bst_parse_duration_us(S("5Y"), &v));
	ASSERT(!bst_parse_duration_us(S("999999999999y"), &v));
	ASSERT(!bst_parse_duration_us(S("5mm"), &v));
	ASSERT(!bst_parse_duration_us(S("1.5s"), &v));
	ASSERT(!bst_parse_duration_us(S("-1s"), &v));
	ASSERT(!bst_parse_duration_us(S("99999999999999999d"), &v));
	ASSERT(!bst_parse_duration_us(S("18446744073709551616us"), &v));
	ASSERT(bst_parse_duration_us(S("18446744073709551615us"), &v) && v == UINT64_MAX);
}

TEST(rate_values)
{
	bst_rate r, q;
	ASSERT(bst_parse_rate(S("100/s"), &r) && r.count == 100 && r.period_us == 1000000);
	ASSERT(bst_parse_rate(S("1k/s"), &r) && r.count == 1024 && r.period_us == 1000000);
	ASSERT(bst_parse_rate(S("6000/m"), &r) && r.count == 6000 && r.period_us == 60000000);
	ASSERT(bst_parse_rate(S("100/s"), &q));
	{
		bst_rate six;
		ASSERT(bst_parse_rate(S("6000/m"), &six));
		ASSERT(bst_rate_eq(&six, &q));
	}
	/* 5/m is not a whole number per second: kept exact, not rounded to 0. */
	ASSERT(bst_parse_rate(S("5/m"), &r) && r.count == 5 && r.period_us == 60000000);
	ASSERT(!bst_rate_eq(&r, &q));
	ASSERT(!bst_parse_rate(S("0/s"), &r));
	ASSERT(!bst_parse_rate(S("0k/s"), &r));
	ASSERT(!bst_parse_rate(S("100"), &r));
	ASSERT(!bst_parse_rate(S("100/"), &r));
	ASSERT(!bst_parse_rate(S("/s"), &r));
	ASSERT(!bst_parse_rate(S("100/h"), &r));
	ASSERT(!bst_parse_rate(S("100/S"), &r));
	ASSERT(!bst_parse_rate(S("1.5/s"), &r));
	ASSERT(!bst_parse_rate(S("100/s "), &r));
	ASSERT(!bst_parse_rate(S("99999999999g/s"), &r));
	ASSERT(!bst_parse_rate(S("-1/s"), &r));
	ASSERT(!bst_parse_rate(S("010/s"), &r));
	/* k overflow is checked: 2^54 * 1024 = 2^64. */
	ASSERT(!bst_parse_rate(S("18014398509481984k/s"), &r));
	ASSERT(!bst_parse_rate(S("18014398509481985k/s"), &r)); /* wraps to 1024 if unchecked */
	ASSERT(bst_parse_rate(S("18014398509481983k/s"), &r));
	/* Equality is exact even when 64-bit cross products would wrap to equal. */
	bst_rate a = { 1ull << 63, 2 }, b = { 1ull << 63, 4 };
	ASSERT(!bst_rate_eq(&a, &b));
	ASSERT(bst_rate_eq(&a, &a));
}

TEST(mode_values)
{
	uint32_t m;
	ASSERT(bst_parse_mode(S("0600"), &m) && m == 0600);
	ASSERT(bst_parse_mode(S("755"), &m) && m == 0755);
	ASSERT(bst_parse_mode(S("07777"), &m) == false); /* too long */
	ASSERT(bst_parse_mode(S("4755"), &m) && m == 04755);
	ASSERT(!bst_parse_mode(S("0800"), &m));
	ASSERT(!bst_parse_mode(S("60"), &m));
	ASSERT(!bst_parse_mode(S("0o600"), &m));
	ASSERT(!bst_parse_mode(S("-600"), &m));
	ASSERT(!bst_parse_mode(S(""), &m));
}

TEST(bool_enum_kv_int)
{
	bool b = false;
	ASSERT(bst_parse_bool(S("on"), &b) && b);
	ASSERT(bst_parse_bool(S("off"), &b) && !b);
	ASSERT(!bst_parse_bool(S("true"), &b));
	ASSERT(!bst_parse_bool(S("yes"), &b));
	ASSERT(!bst_parse_bool(S("ON"), &b));
	ASSERT(!bst_parse_bool(S("1"), &b));
	ASSERT(!bst_parse_bool(S(""), &b));

	size_t idx = 99;
	ASSERT(bst_parse_enum(S("tx"), ev_ktls, &idx) && idx == 1);
	ASSERT(bst_parse_enum(S("tx+rx"), ev_ktls, &idx) && idx == 2);
	ASSERT(!bst_parse_enum(S("t"), ev_ktls, &idx));
	ASSERT(!bst_parse_enum(S("TX"), ev_ktls, &idx));
	ASSERT(!bst_parse_enum(S(""), ev_ktls, &idx));

	int64_t i;
	ASSERT(bst_parse_int(S("503"), 100, 599, &i) && i == 503);
	ASSERT(bst_parse_int(S("-5"), -10, 10, &i) && i == -5);
	ASSERT(!bst_parse_int(S("600"), 100, 599, &i));
	ASSERT(!bst_parse_int(S("99999999999999999999"), INT64_MIN, INT64_MAX, &i));
	ASSERT(bst_parse_int(S("-9223372036854775808"), INT64_MIN, INT64_MAX, &i) &&
	       i == INT64_MIN);
	ASSERT(!bst_parse_int(S("9223372036854775808"), INT64_MIN, INT64_MAX, &i));
	ASSERT(!bst_parse_int(S("-"), -10, 10, &i));
	ASSERT(!bst_parse_int(S("+1"), -10, 10, &i));
	ASSERT(!bst_parse_int(S("1 "), -10, 10, &i));

	uint8_t p;
	ASSERT(bst_parse_percent(S("10%"), &p) && p == 10);
	ASSERT(bst_parse_percent(S("100%"), &p) && p == 100);
	ASSERT(bst_parse_percent(S("0%"), &p) && p == 0);
	ASSERT(!bst_parse_percent(S("101%"), &p));
	ASSERT(!bst_parse_percent(S("10"), &p));
	ASSERT(!bst_parse_percent(S("%"), &p));
	ASSERT(!bst_parse_percent(S("1.5%"), &p));
	ASSERT(!bst_parse_percent(S("010%"), &p));
	ASSERT(!bst_parse_percent(S("-0%"), &p));
	ASSERT(!bst_parse_int(S("-0"), -10, 10, &i));
	ASSERT(!bst_parse_int(S("007"), 0, 10, &i));
	ASSERT(bst_parse_int(S("0"), 0, 10, &i) && i == 0);

	bst_str val = { 0 };
	bool seen = false;
	ASSERT_EQ(bst_parse_kv(S("weight=2"), "weight=", &val, &seen), 1);
	ASSERT(seen && val.len == 1 && val.p[0] == '2');
	ASSERT_EQ(bst_parse_kv(S("weight=3"), "weight=", &val, &seen), -1); /* repeated */
	seen = false;
	ASSERT_EQ(bst_parse_kv(S("weight="), "weight=", &val, &seen), -1);  /* empty */
	ASSERT_EQ(bst_parse_kv(S("other=1"), "weight=", &val, &seen), 0);
	ASSERT_EQ(bst_parse_kv(S("weigh"), "weight=", &val, &seen), 0);
	ASSERT_EQ(bst_parse_kv(S("weight"), "weight=", &val, &seen), 0);
	ASSERT_EQ(bst_parse_kv(S("weight=a=b"), "weight=", &val, &seen), 1);
	ASSERT(val.len == 3);
}

/* ---- Validation ---- */

TEST(full_example_validates)
{
	FILE *f = fopen("fuzz/corpus/cfg/full_example.conf", "rb");
	ASSERT(f != NULL);
	static char buf[1 << 16];
	size_t n = fread(buf, 1, sizeof buf - 1, f);
	fclose(f);
	buf[n] = 0;
	ASSERT(n > 1000);
	/* The file's trailing `include` matches nothing here and is spliced away. */
	int rc = validate(buf);
	if (rc != 0)
		printf("# %s:%d:%d: %s\n", E.file ? E.file : "-", E.line, E.col, E.msg);
	ASSERT_EQ(rc, 0);
}

/* Every simple config in config-language.md validates against the fixture: the document and
 * the schema cannot drift apart unnoticed. The blocks are read from the document itself. */
TEST(simple_configs_from_the_language_doc_validate)
{
	FILE *f = fopen("docs/implementation-plan/config-language.md", "rb");
	ASSERT(f != NULL);
	static char doc[1 << 17];
	size_t n = fread(doc, 1, sizeof doc - 1, f);
	fclose(f);
	doc[n] = 0;
	char *p = strstr(doc, "## Simple configs"), *end = strstr(doc, "## Full example");
	ASSERT(p != NULL && end != NULL && p < end);
	int blocks = 0;
	while ((p = strstr(p, "```nginx\n")) != NULL && p < end) {
		p += 9;
		char *close = strstr(p, "```");
		ASSERT(close != NULL);
		char saved = *close;
		*close = 0;
		int rc = validate(p);
		if (rc != 0)
			TAP_FAIL_("simple config %d: %s at %d:%d", blocks + 1, E.msg, E.line, E.col);
		*close = saved;
		blocks++;
		p = close + 3;
	}
	ASSERT_EQ(blocks, 3); /* static site, HTTPS with tls auto, reverse proxy */
}

TEST(upstream_balance_alternatives_are_exclusive)
{
	ASSERT_EQ(validate("upstream u { balance least_conn; balance peak_ewma; }"), -1);
	ASSERT(has("duplicate \"balance\""));
	ASSERT_EQ(validate("upstream u { balance hash $uri; }"), 0);
	ASSERT_EQ(validate("upstream u { tls verify on; tls ca /x; balance round_robin; }"), 0);
}

TEST(log_format_fields)
{
	ASSERT_EQ(validate("log_format main json { time $time_iso8601; client $remote_addr;"
			   " status $status; time $again; }"), 0);
	ASSERT_EQ(validate("log_format main json { time; }"), -1);
	ASSERT(has("\"time\""));
	ASSERT(has("at least 1"));
	/* The catch-all is per context: other blocks still reject unknown names. */
	ASSERT_EQ(validate("server { time $x; }"), -1);
	ASSERT(has("unknown directive \"time\""));
	ASSERT_EQ(validate("log_format main json { time $x { } }"), -1);
}

TEST(expires_year)
{
	ASSERT_EQ(validate("server { expires 1y immutable; }"), 0);
	ASSERT_EQ(validate("server { expires 1Y; }"), -1);
}

TEST(two_word_directives)
{
	ASSERT_EQ(validate("upstream u { tls verify on; tls ca /x; }"), 0);
	ASSERT_EQ(validate("upstream u { tls verify on; tls verify off; }"), -1);
	ASSERT(has("duplicate"));
	ASSERT(has("tls verify"));
	ASSERT_EQ(validate("upstream u { tls verify maybe; }"), -1);
	ASSERT(has("on or off"));
	ASSERT_EQ(validate("upstream u { balance hash $key; }"), 0);
	ASSERT_EQ(validate("upstream u { balance round_robin; }"), 0);
	ASSERT_EQ(validate("upstream u { balance hash; }"), -1);
	ASSERT(has("at least 1"));
	ASSERT_EQ(validate("upstream u { balance round_robin $key; }"), -1);
	ASSERT(has("at most 0"));
	ASSERT_EQ(validate("upstream u { balance hash $a; balance hash $b; }"), -1);
	ASSERT(has("duplicate"));
	/* Unknown subname: suggestion from the valid ones. */
	ASSERT_EQ(validate("upstream u { tls vrify on; }"), -1);
	ASSERT(has("did you mean \"verify\"?"));
	ASSERT_EQ(validate("upstream u { balance zzzzzzzz; }"), -1);
	ASSERT(!has("did you mean"));
	ASSERT(has("round_robin"));
	ASSERT_EQ(validate("upstream u { tls; }"), -1);
	ASSERT(has("ca, verify"));
	/* The same name in another context is unaffected. */
	ASSERT_EQ(validate("server { tls_profile m; }"), 0);
	ASSERT_EQ(validate("server { tls verify on; }"), -1); /* `tls auto` exists here, not verify */
	ASSERT(has("unknown \"tls\" subcommand \"verify\""));
	ASSERT_EQ(validate("limit_zone z { tls verify on; }"), -1);
	ASSERT(has("not valid in limit_zone; valid in: upstream, server"));
}

TEST(keywords_and_lists)
{
	ASSERT_EQ(validate("workers auto;"), 0);
	ASSERT_EQ(validate("workers 4;"), 0);
	ASSERT_EQ(validate("workers banana;"), -1);
	ASSERT(has("auto"));
	ASSERT_EQ(validate("workers 0;"), -1);
	ASSERT_EQ(validate("upstream u { retry on=connect_error,502,503,504; }"), 0);
	ASSERT_EQ(validate("upstream u { retry on=502; }"), 0);
	ASSERT_EQ(validate("upstream u { retry on=connect_error,,502; }"), -1);
	ASSERT(has("empty element"));
	ASSERT_EQ(validate("upstream u { retry on=connect_error,; }"), -1);
	ASSERT_EQ(validate("upstream u { retry on=bogus; }"), -1);
	ASSERT_EQ(validate("upstream u { retry on=502,700; }"), -1);
	ASSERT_EQ(validate("upstream u { retry on=; }"), -1);
	ASSERT_EQ(validate("upstream u { retry on=$x; }"), -1);
	ASSERT(has("variable"));
}

TEST(mode_option)
{
	ASSERT_EQ(validate("admin { socket /run/a.sock mode=0600; }"), 0);
	ASSERT_EQ(validate("admin { socket /run/a.sock mode=0900; }"), -1);
	ASSERT_EQ(validate("admin { socket /run/a.sock mode=; }"), -1);
}

TEST(quoted_options)
{
	ASSERT_EQ(validate("upstream u { health_check \"path=/a b\" interval=5s; }"), 0);
	ASSERT_EQ(validate("upstream u { health_check \"interval=5\"; }"), -1);
	ASSERT(has("duration"));
	/* Undeclared quoted words stay positional. */
	ASSERT_EQ(validate("server { root \"weight=2\"; }"), 0);
	ASSERT_EQ(validate("server { location \"a=b\" { } }"), 0);
}

TEST(option_typos)
{
	ASSERT_EQ(validate("limit_zone z { rate 100/s bursst=200; }"), -1);
	ASSERT(has("bursst"));
	ASSERT(has("did you mean \"burst=\"?"));
	ASSERT_EQ(E.col, 27);
	ASSERT_EQ(validate("cache_store c { disk /d siz=50g; }"), -1);
	ASSERT(has("siz="));
	ASSERT(has("size="));
	ASSERT_EQ(validate("cache_store c { disk siz=50g; }"), -1);
	ASSERT_EQ(validate("server { root weight=2; }"), -1);
	ASSERT(has("takes no options"));
	/* Not option-shaped: variables, URLs, modifiers, quoted templates. */
	ASSERT_EQ(validate("server { location / { try_files $uri?y=2 /x; } }"), 0);
	ASSERT_EQ(validate("server { location / { proxy http://h/?a=b; } }"), 0);
	ASSERT_EQ(validate("server { location = /x { } }"), 0);
	ASSERT_EQ(validate("server { location / { try_files \"a=$b\" /x; } }"), 0);
	ASSERT_EQ(validate("server { location ~ x=y { } }"), -1); /* bare: quote it */
	ASSERT_EQ(validate("server { location ~ \"x=y\" { } }"), 0);
	ASSERT_EQ(validate("server { root Foo=bar; }"), 0); /* not shaped like an option */
}

TEST(accessors)
{
	ASSERT_EQ(validate("server { listen 443 tcp_profile=edge http2; }"), 0);
	const bst_ast_node *n = AST->root.children->children;
	const bst_directive *d = bst_schema_find(SC, n->name, n->name_len, BST_CTX_SERVER);
	ASSERT(d != NULL);
	ASSERT(!bst_dir_has_require(d, n)); /* listen does not declare `require` */
	ASSERT_EQ(bst_dir_npos(d, n), 2);
	ASSERT_STR(bst_dir_pos(d, n, 0)->text, "443");
	ASSERT_STR(bst_dir_pos(d, n, 1)->text, "http2");
	ASSERT(bst_dir_pos(d, n, 2) == NULL);
	bst_ast_arg v;
	ASSERT(bst_dir_opt(d, n, "tcp_profile=", &v));
	ASSERT_EQ(v.len, 4);
	ASSERT(memcmp(v.text, "edge", 4) == 0);
	ASSERT_EQ(v.loc.col, 21);
	ASSERT_EQ(v.tpl_len, 4);
	ASSERT(memcmp(v.tpl, "edge", 4) == 0);
	ASSERT(!bst_dir_opt(d, n, "nope=", &v));

	ASSERT_EQ(validate("server { listen 443; }"), 0);
	n = AST->root.children->children;
	ASSERT_EQ(bst_dir_npos(d, n), 1);
	/* The trailing flag, where a directive declares it. */
	ASSERT_EQ(validate("tls_profile m { ktls tx require; }"), 0);
	n = AST->root.children->children;
	const bst_directive *kd = bst_schema_find(SC, n->name, n->name_len, BST_CTX_TLS_PROFILE);
	ASSERT(kd != NULL && bst_dir_has_require(kd, n));
	ASSERT_EQ(bst_dir_npos(kd, n), 1);
	ASSERT_STR(bst_dir_pos(kd, n, 0)->text, "tx");
	/* A quoted "require" is a value, not the flag. */
	ASSERT_EQ(validate("tls_profile m { ktls tx \"require\"; }"), -1);
	/* Undeclared require is not stripped. */
	ASSERT_EQ(validate("server { listen 80 require; }"), -1);
	ASSERT_EQ(validate("server { root /x require; }"), -1);

	/* Two-word directive: positions count after the subname. */
	ASSERT_EQ(validate("upstream u { balance hash $key; }"), 0);
	n = AST->root.children->children;
	d = bst_schema_find_sub(SC, n->name, n->name_len, BST_CTX_UPSTREAM, "hash", 4);
	ASSERT(d != NULL);
	ASSERT_EQ(bst_dir_npos(d, n), 1);
	ASSERT_STR(bst_dir_pos(d, n, 0)->text, "$key");
}

TEST(unknown_directive_suggestion)
{
	ASSERT_EQ(validate("server { location / { proxi up; } }"), -1);
	ASSERT(has("unknown directive \"proxi\""));
	ASSERT(has("did you mean \"proxy\"?"));
	ASSERT_STR(E.file, "t.conf");
	ASSERT_EQ(E.line, 1);
	ASSERT_EQ(E.col, 23);

	ASSERT_EQ(validate("server { frobnicate_widgets 1; }"), -1);
	ASSERT(has("unknown directive \"frobnicate_widgets\""));
	ASSERT(!has("did you mean"));

	/* Distance 2 is suggested; 3 and 4 are not ("proxy" is valid in server). */
	ASSERT_EQ(validate("server { proxxyz a; }"), -1);
	ASSERT(has("did you mean \"proxy\"?"));
	ASSERT_EQ(validate("server { proxzzz a; }"), -1);
	ASSERT(!has("did you mean"));
	ASSERT_EQ(validate("server { prxyyyy a; }"), -1);
	ASSERT(!has("did you mean"));

	/* Only names valid in the current context are suggested ("workers" is global). */
	ASSERT_EQ(validate("server { workerz 1; }"), -1);
	ASSERT(!has("did you mean"));
	ASSERT_EQ(validate("workerz 1;"), -1);
	ASSERT(has("did you mean \"workers\"?"));

	/* A very long name is just unknown (no buffer overrun in the distance code). */
	char big[400];
	memset(big, 'a', sizeof big);
	memcpy(big, "server { ", 9);
	memcpy(big + 9, "pro", 3);
	memcpy(big + sizeof big - 5, "; }", 4);
	big[sizeof big - 1] = 0;
	ASSERT_EQ(validate(big), -1);
	ASSERT(!has("did you mean"));
}

TEST(suggestion_tie_is_deterministic)
{
	/* "aad" is distance 1 from both "aab" and "aac"; registration order is reversed
	 * on purpose: the alphabetically first name wins whatever the order. */
	bst_directive t[2] = {
		D("aac", G, A1(STR)),
		D("aab", G, A1(STR)),
	};
	bst_dirtab tab = { t, 2 };
	const bst_dirtab *tabs[] = { &tab };
	bst_err e;
	bst_schema *s = bst_schema_build(tabs, 1, &e);
	ASSERT(s != NULL);
	bst_ast *ast = parse("aad x;");
	ASSERT(ast != NULL);
	ASSERT_EQ(bst_cfg_validate_with(s, ast, &E), -1);
	ASSERT(has("did you mean \"aab\"?"));
	bst_schema_free(s);
}

TEST(wrong_context)
{
	ASSERT_EQ(validate("upstream api { root /x; }"), -1);
	ASSERT(has("\"root\""));
	ASSERT(has("upstream"));
	ASSERT(has("valid in: server, location"));
	ASSERT_EQ(E.line, 1);
	ASSERT_EQ(E.col, 16);
	ASSERT_EQ(validate("root /x;"), -1);
	ASSERT(has("not valid in global"));
	ASSERT(has("valid in: server, location"));
}

TEST(duplicate_scalar)
{
	ASSERT_EQ(validate("server {\n  root /a;\n  root /b;\n}"), -1);
	ASSERT(has("duplicate"));
	ASSERT(has("\"root\""));
	ASSERT_EQ(E.line, 3);
	ASSERT_EQ(E.col, 3);
	ASSERT(has("t.conf:2:3"));
	ASSERT_EQ(validate("server { root /a; location /x { root /b; } location /y { root /c; } }"), 0);
	ASSERT_EQ(validate("server { listen 80; listen 443; }"), 0);
	ASSERT_EQ(validate("server { root /a; } server { root /b; }"), 0);
	ASSERT_EQ(validate("server { root /a; location / { } root /b; }"), -1);
	/* A nested scope must not disturb the parent's record. */
	ASSERT_EQ(validate("server { root /a; location / { root /b; } root /c; }"), -1);
	ASSERT_EQ(E.col, 43);
	ASSERT_EQ(validate("server { location / { root /b; } root /c; }"), 0);
}

TEST(repeat_last_type)
{
	ASSERT_EQ(validate("nums a 1 2 3;"), 0);
	ASSERT_EQ(validate("nums a 1 x;"), -1);
	ASSERT(has("integer"));
	ASSERT_EQ(validate("nums 1 2 3 4 5;"), -1);
}

TEST(hand_built_too_deep_ast)
{
	/* The parser caps nesting at BST_CFG_MAX_NESTING; the validator must not trust that. */
	enum { N = BST_CFG_MAX_NESTING + 8 };
	static bst_ast_node nodes[N];
	static bst_ast_arg arg;
	arg = (bst_ast_arg){ .kind = BST_TOK_WORD, .text = "/", .len = 1, .tpl = "/", .tpl_len = 1 };
	bst_ast ast;
	memset(&ast, 0, sizeof ast);
	memset(nodes, 0, sizeof nodes);
	for (int i = 0; i < N; i++) {
		nodes[i].name = i == 0 ? "server" : "location";
		nodes[i].name_len = i == 0 ? 6 : 8;
		nodes[i].has_block = 1;
		nodes[i].children = i + 1 < N ? &nodes[i + 1] : NULL;
		nodes[i].loc = (bst_loc){ "h", 1, 1 };
		if (i > 0) {
			nodes[i].args = &arg;
			nodes[i].nargs = 1;
		}
	}
	ast.root.children = &nodes[0];
	ASSERT_EQ(bst_cfg_validate_with(SC, &ast, &E), -1);
	ASSERT(has("nested deeper"));
}

TEST(arg_errors)
{
	ASSERT_EQ(validate("limits { worker_memory 1x; }"), -1);
	ASSERT(has("size"));
	ASSERT_EQ(E.col, 24);
	ASSERT_EQ(validate("limits { overload_retry_after 5; }"), -1);
	ASSERT(has("duration"));
	ASSERT_EQ(validate("limits { overload_status 700; }"), -1);
	ASSERT(has("100"));
	ASSERT_EQ(validate("xdp { mode fast; }"), -1);
	ASSERT(has("auto, native, generic"));
	ASSERT_EQ(validate("xdp { allow 10.0.0.1/8; }"), -1);
	ASSERT_EQ(validate("io { uring_sqpoll true; }"), -1);
	ASSERT(has("on or off"));
	ASSERT_EQ(validate("workers;"), -1);
	ASSERT(has("at least 1"));
	ASSERT_EQ(E.line, 1);
	ASSERT_EQ(E.col, 1);
	ASSERT_EQ(validate("workers 1 2;"), -1);
	ASSERT(has("at most 1"));
	ASSERT_EQ(validate("workers 4 { }"), -1);
	ASSERT(has("does not take a block"));
	ASSERT_EQ(validate("server;"), -1);
	ASSERT(has("requires a block"));
	ASSERT_EQ(validate("tls_profile m { ktls tx require; }"), 0);
	ASSERT_EQ(validate("tls_profile m { ktls tx require require; }"), -1);
	ASSERT_EQ(validate("tls_profile m { ktls require; }"), -1);
	ASSERT_EQ(validate("server { root \"\"; }"), -1);
	ASSERT(has("non-empty path"));
}

TEST(option_errors)
{
	ASSERT_EQ(validate("tcp_profile e { keepalive idle=60s idle=1s; }"), -1);
	ASSERT(has("repeated"));
	ASSERT_EQ(E.col, 36);
	ASSERT_EQ(validate("tcp_profile e { keepalive idle=; }"), -1);
	ASSERT(has("empty"));
	ASSERT_EQ(validate("tcp_profile e { keepalive interval=1s; }"), -1);
	ASSERT(has("idle="));
	ASSERT_EQ(E.line, 1);
	ASSERT_EQ(E.col, 17);
	ASSERT_EQ(validate("tcp_profile e { keepalive idle=60; }"), -1);
	ASSERT(has("duration"));
	ASSERT_EQ(E.col, 27);
	ASSERT_EQ(validate("tcp_profile e { keepalive idle=1s count=0; }"), -1);
	ASSERT_EQ(validate("tcp_profile e { keepalive idle=1s stray; }"), -1);
	ASSERT(has("at most 0"));
	ASSERT_EQ(validate("upstream u { retry budget=200%; }"), -1);
	ASSERT_EQ(validate("upstream u { retry budget=-0%; }"), -1);
	ASSERT_EQ(validate("limit_zone z { rate 0/s; }"), -1);
}

TEST(variables)
{
	ASSERT_EQ(validate("limit_zone z { key $remote_addr; }"), 0);
	ASSERT_EQ(validate("limits { worker_memory $mem; }"), -1);
	ASSERT(has("variable"));
	ASSERT_EQ(validate("server { root $docroot; }"), -1);
	ASSERT(has("variable"));
	ASSERT_EQ(validate("server { root \"/srv/$host\"; }"), -1);
	ASSERT(has("variable"));
	ASSERT_EQ(validate("tcp_profile e { keepalive idle=$x; }"), -1);
	ASSERT_EQ(validate("server { root '/srv/$host'; }"), 0);
	ASSERT_EQ(validate("server { location ~ \"^/a$\" { } }"), 0);
	ASSERT_EQ(validate("server { root \"/srv/$$host\"; }"), 0); /* $$ is a literal $ */
}

TEST(messages_are_sanitized)
{
	ASSERT_EQ(validate("limits { worker_memory \"a\\tb\\\"c\"; }"), -1);
	ASSERT(has("a?b?c"));
	char cfg[300];
	memset(cfg, 'x', sizeof cfg);
	memcpy(cfg, "limits { worker_memory ", 23);
	memcpy(cfg + sizeof cfg - 5, "; }", 4);
	cfg[sizeof cfg - 1] = 0;
	ASSERT_EQ(validate(cfg), -1);
	ASSERT(has("..."));
	ASSERT(strlen(E.msg) < 200);
}

TEST(env_dollar_is_not_a_variable)
{
	setenv("BST_T_DOLLAR", "/srv/$host", 1);
	ASSERT_EQ(validate("server { root ${BST_T_DOLLAR}; }"), 0);
	unsetenv("BST_T_DOLLAR");
}

TEST(deep_nesting_is_iterative)
{
	char buf[4096];
	size_t n = 0;
	n += (size_t)snprintf(buf + n, sizeof buf - n, "server {");
	for (int i = 0; i < 60; i++)
		n += (size_t)snprintf(buf + n, sizeof buf - n, " location /a {");
	for (int i = 0; i < 60; i++)
		n += (size_t)snprintf(buf + n, sizeof buf - n, " }");
	snprintf(buf + n, sizeof buf - n, " }");
	ASSERT_EQ(validate(buf), 0);
}

TEST(many_siblings_are_linear)
{
	size_t cap = 50000 * 14 + 64;
	char *buf = malloc(cap);
	ASSERT(buf != NULL);
	size_t n = (size_t)snprintf(buf, cap, "server {");
	for (int i = 0; i < 50000; i++)
		n += (size_t)snprintf(buf + n, cap - n, " listen 80;");
	snprintf(buf + n, cap - n, " }");
	int rc = validate(buf);
	free(buf);
	ASSERT_EQ(rc, 0);
}

/* ---- Table integrity ---- */

TEST(all_directives_documented)
{
	/* The fixture, then whatever the real registry holds (no fixed count). */
	bst_err e;
	size_t total = 0;
	for (size_t i = 0; i < fx_tab.n; i++) {
		ASSERT(fx_tab.dirs[i].doc != NULL && fx_tab.dirs[i].doc[0] != 0);
		ASSERT_EQ(bst_directive_check(&fx_tab.dirs[i], &e), 0);
		total++;
	}
	ASSERT(total > 100);
	const bst_schema *reg = bst_schema_registry(&e);
	if (reg == NULL)
		printf("# registry: %s\n", e.msg);
	ASSERT(reg != NULL);
	size_t ntabs;
	const bst_dirtab *const *tabs = bst_dirtabs(&ntabs);
	for (size_t t = 0; t < ntabs; t++) {
		for (size_t i = 0; i < tabs[t]->n; i++) {
			const bst_directive *d = &tabs[t]->dirs[i];
			ASSERT(d->doc != NULL && d->doc[0] != 0);
			if (bst_directive_check(d, &e) != 0)
				printf("# %s\n", e.msg);
			ASSERT_EQ(bst_directive_check(d, &e), 0);
		}
	}
}

TEST(integrity_failures)
{
	bst_err e;
	bst_directive d = { .name = "x", .contexts = BST_CTX_GLOBAL, .doc = "d", .apply = fx_noop,
			    .args = { .min_args = 1, .max_args = 1, .pos = { STR } } };
	bst_dirtab tab = { &d, 1 };
	const bst_dirtab *tabs[] = { &tab };

	bst_schema *s = bst_schema_build(tabs, 1, &e);
	ASSERT(s != NULL);
	bst_schema_free(s);

	d.doc = "";
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	ASSERT(strstr(e.msg, "doc") != NULL);
	d.doc = NULL;
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	d.doc = "d";

	d.apply = NULL; /* required in every build, tests included */
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	ASSERT(strstr(e.msg, "apply") != NULL);
	d.apply = fx_noop;

	d.default_value = "a b";
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	ASSERT(strstr(e.msg, "default") != NULL);
	d.default_value = NULL;

	d.args.pos[0].kind = BST_T_SIZE;
	d.default_value = "12x";
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	d.default_value = "12k";
	s = bst_schema_build(tabs, 1, &e);
	ASSERT(s != NULL);
	bst_schema_free(s);
	d.default_value = NULL;

	d.contexts = 0;
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	d.contexts = BST_CTX_GLOBAL;

	d.args.pos[0].kind = BST_T_ENUM;
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	d.args.pos[0].kind = BST_T_INT;
	d.args.pos[0].min = 5;
	d.args.pos[0].max = 1;
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	ASSERT(strstr(e.msg, "min > max") != NULL);
	d.args.pos[0] = (bst_argtype)STR;

	const char *badnames[] = { "Bad", "a-b", "a b", "", "x.y" };
	for (size_t i = 0; i < sizeof badnames / sizeof badnames[0]; i++) {
		d.name = badnames[i];
		ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	}
	d.name = "x";

	static const bst_optspec longo[] = {
		O("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=", STR)
	};
	d.args.opts = longo;
	d.args.nopts = 1;
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	static const bst_optspec dupo[] = { O("a=", STR), O("a=", STR) };
	d.args.opts = dupo;
	d.args.nopts = 2;
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	d.args.nopts = 0;
	d.args.opts = NULL;

	d.args.block = BST_BLOCK_OPTIONAL;
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	d.args.block = BST_BLOCK_FORBIDDEN;
	d.child_ctx = BST_CTX_SERVER;
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	d.child_ctx = 0;

	/* any_name needs repeatable; a subname cannot be combined with it. */
	d.any_name = true;
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
	d.repeatable = true;
	s = bst_schema_build(tabs, 1, &e);
	ASSERT(s != NULL);
	bst_schema_free(s);
	d.subname = "sub";
	ASSERT(bst_schema_build(tabs, 1, &e) == NULL);
}

TEST(duplicate_names_overlapping_contexts)
{
	bst_err e;
	bst_directive a[2] = {
		D("dup", BST_CTX_SERVER | BST_CTX_LOCATION, A1(STR)),
		D("dup", BST_CTX_LOCATION | BST_CTX_UPSTREAM, A1(STR)),
	};
	bst_dirtab t1 = { &a[0], 1 }, t2 = { &a[1], 1 };
	const bst_dirtab *tabs[] = { &t1, &t2 };
	ASSERT(bst_schema_build(tabs, 2, &e) == NULL);
	ASSERT(strstr(e.msg, "dup") != NULL);
	ASSERT(strstr(e.msg, "location") != NULL);

	a[1].contexts = BST_CTX_UPSTREAM;
	bst_schema *s = bst_schema_build(tabs, 2, &e);
	ASSERT(s != NULL);
	ASSERT(bst_schema_find(s, "dup", 3, BST_CTX_SERVER) == &a[0]);
	ASSERT(bst_schema_find(s, "dup", 3, BST_CTX_UPSTREAM) == &a[1]);
	ASSERT(bst_schema_find(s, "dup", 3, BST_CTX_GLOBAL) == NULL);
	ASSERT(bst_schema_find(s, "du", 2, BST_CTX_SERVER) == NULL);
	ASSERT(bst_schema_find(s, "dupx", 4, BST_CTX_SERVER) == NULL);
	bst_schema_free(s);

	bst_directive b[2] = { a[0], a[0] };
	bst_dirtab t3 = { b, 2 };
	const bst_dirtab *tabs3[] = { &t3 };
	ASSERT(bst_schema_build(tabs3, 1, &e) == NULL);

	/* Two-word entries: same name and different subnames coexist; same subname, or a
	 * plain entry beside a subname entry, collide. */
	bst_directive c[2] = {
		D("two", G, .subname = "a", A1(STR)),
		D("two", G, .subname = "b", A1(STR)),
	};
	bst_dirtab t4 = { c, 2 };
	const bst_dirtab *tabs4[] = { &t4 };
	s = bst_schema_build(tabs4, 1, &e);
	ASSERT(s != NULL);
	ASSERT(bst_schema_find_sub(s, "two", 3, G, "b", 1) == &c[1]);
	ASSERT(bst_schema_find_sub(s, "two", 3, G, "c", 1) == NULL);
	bst_schema_free(s);
	c[1].subname = "a";
	ASSERT(bst_schema_build(tabs4, 1, &e) == NULL);
	c[1].subname = NULL;
	ASSERT(bst_schema_build(tabs4, 1, &e) == NULL);
}

TEST(registry_is_built_once)
{
	bst_err e;
	const bst_schema *a = bst_schema_registry(&e);
	const bst_schema *b = bst_schema_registry(&e);
	ASSERT(a != NULL && a == b);
}

TEST(context_names)
{
	ASSERT_STR(bst_ctx_name(BST_CTX_GLOBAL), "global");
	ASSERT_STR(bst_ctx_name(BST_CTX_TCP_PROFILE), "tcp_profile");
	ASSERT_STR(bst_ctx_name(BST_CTX_ACME), "acme");
	ASSERT_STR(bst_ctx_name(BST_CTX_SERVER | BST_CTX_LOCATION), "?");
	ASSERT_STR(bst_ctx_name(0), "?");
}

/* ---- Bounds for size, duration and rate ---- */

static const bst_directive bound_dirs[] = {
	D("bsz", G, A1(((bst_argtype){ .kind = BST_T_SIZE, .min = 1024, .max = 1 << 20 }))),
	D("bdur", G, A1(((bst_argtype){ .kind = BST_T_DURATION, .min = 1000000,
					.max = 3600000000LL }))),
	D("brate", G, A1(((bst_argtype){ .kind = BST_T_RATE, .min = 1, .max = 1000 }))),
	D("bmin", G, A1(((bst_argtype){ .kind = BST_T_SIZE, .min = 1 }))), /* no upper bound */
};

static int validate_in(const bst_dirtab *tab, const char *text)
{
	bst_schema *s = bst_schema_build((const bst_dirtab *const[]){ tab }, 1, &E);
	if (s == NULL)
		return -3;
	bst_ast *ast = parse(text);
	int rc = ast ? bst_cfg_validate_with(s, ast, &E) : -2;
	bst_schema_free(s);
	return rc;
}

#define VAL_IN(tab, text, want)                                                         \
	do {                                                                            \
		int rc_ = validate_in(&(tab), text);                                    \
		if (rc_ != (want))                                                      \
			TAP_FAIL_("%s: got %d want %d (%s)", text, rc_, (int)(want), E.msg); \
	} while (0)

TEST(size_duration_rate_bounds)
{
	bst_dirtab t = { bound_dirs, sizeof bound_dirs / sizeof bound_dirs[0] };
	VAL_IN(t, "bsz 1023;", -1);
	ASSERT(has("size between 1024 bytes and 1048576 bytes"));
	VAL_IN(t, "bsz 1k;", 0);
	VAL_IN(t, "bsz 1m;", 0);
	VAL_IN(t, "bsz 1048577;", -1);
	VAL_IN(t, "bsz 2m;", -1);
	VAL_IN(t, "bdur 999ms;", -1);
	ASSERT(has("duration between 1000000us and 3600000000us"));
	VAL_IN(t, "bdur 1s;", 0);
	VAL_IN(t, "bdur 1h;", 0);
	VAL_IN(t, "bdur 3601s;", -1);
	VAL_IN(t, "bdur 0s;", -1);
	VAL_IN(t, "brate 1/s;", 0);
	VAL_IN(t, "brate 1000/s;", 0);
	VAL_IN(t, "brate 1001/s;", -1);
	ASSERT(has("rate between 1/s and 1000/s"));
	VAL_IN(t, "brate 59/m;", -1); /* just under one per second */
	VAL_IN(t, "brate 60/m;", 0);  /* exactly one per second */
	VAL_IN(t, "brate 1k/s;", -1); /* 1024/s */
	VAL_IN(t, "brate 60000/m;", 0); /* exactly 1000/s */
	VAL_IN(t, "bmin 0;", -1);
	VAL_IN(t, "bmin 18446744073709551615;", 0); /* no upper bound: the full range */
	/* A reversed range is an integrity error. */
	static const bst_directive rev[] = {
		D("r", G, A1(((bst_argtype){ .kind = BST_T_SIZE, .min = 10, .max = 5 }))) };
	bst_dirtab tr = { rev, 1 };
	ASSERT(bst_schema_build((const bst_dirtab *const[]){ &tr }, 1, &E) == NULL);
}

/* ---- Control bytes and empty strings ---- */

TEST(control_bytes_in_strings_and_paths_are_rejected)
{
	ASSERT_EQ(validate("server { name \"a\033]0;x\007b\"; }"), -1);
	ASSERT(has("control byte 0x1b"));
	ASSERT_EQ(E.col, 15);
	ASSERT_EQ(validate("server { root \"/a\007b\"; }"), -1);
	ASSERT(has("control byte 0x07"));
	ASSERT_EQ(validate("server { name \"a\x7f\"; }"), -1);
	ASSERT_EQ(validate("server { name \"a\tb\"; }"), 0); /* tab is allowed */
	ASSERT_EQ(validate("server { name \"caf\xc3\xa9\"; }"), 0); /* UTF-8 is not a control byte */
	setenv("BST_T_ESC", "x\033[2Jy", 1); /* an environment value is checked after expansion */
	ASSERT_EQ(validate("server { name ${BST_T_ESC}; }"), -1);
	ASSERT(has("control byte 0x1b"));
	unsetenv("BST_T_ESC");
}

TEST(empty_string_needs_allow_empty)
{
	ASSERT_EQ(validate("server { name \"\"; }"), -1);
	ASSERT(has("non-empty string"));
	static const bst_directive ok[] = {
		D("maybe", G, A1(((bst_argtype){ .kind = BST_T_STRING, .empty_ok = true }))) };
	bst_dirtab t = { ok, 1 };
	VAL_IN(t, "maybe \"\";", 0);
	VAL_IN(t, "maybe \"a\007\";", -1); /* still no control bytes */
	/* An allowed empty value prints quoted and round-trips. */
	bst_schema *s = bst_schema_build((const bst_dirtab *const[]){ &t }, 1, &E);
	ASSERT(s != NULL);
	bst_ast *ast = parse("maybe \"\";");
	ASSERT(ast != NULL);
	char *buf = NULL;
	size_t blen = 0;
	FILE *f = open_memstream(&buf, &blen);
	ASSERT_EQ(bst_cfg_dump(s, ast, f, &E), 0);
	fclose(f);
	ASSERT_STR(buf, "maybe \"\";\n");
	free(buf);
	bst_schema_free(s);
}

/* -T refuses a control byte even where validation lets one through (a template). */
TEST(dump_refuses_control_bytes)
{
	static const bst_directive td[] = { D("tpl", G, A1(TPL)) };
	bst_dirtab t = { td, 1 };
	bst_schema *s = bst_schema_build((const bst_dirtab *const[]){ &t }, 1, &E);
	ASSERT(s != NULL);
	bst_ast *ast = parse("tpl \"a\033[2Jb\";");
	ASSERT(ast != NULL);
	ASSERT_EQ(bst_cfg_validate_with(s, ast, &E), 0);
	FILE *f = tmpfile();
	ASSERT_EQ(bst_cfg_dump(s, ast, f, &E), -1);
	ASSERT(has("control byte (0x1b)"));
	ASSERT_EQ(E.line, 1);
	ASSERT_EQ(E.col, 5);
	ASSERT_EQ(ftell(f), 0); /* nothing was written */
	fclose(f);
	ast = parse("tpl \"a\tb\";");
	f = tmpfile();
	ASSERT_EQ(bst_cfg_dump(s, ast, f, &E), 0);
	fclose(f);
	bst_schema_free(s);
}

TEST(variable_error_hints_single_quotes)
{
	ASSERT_EQ(validate("server { root \"/srv/$host\"; }"), -1);
	ASSERT(has("variable not allowed here"));
	ASSERT(has("single quotes"));
}

TAP_MAIN()
