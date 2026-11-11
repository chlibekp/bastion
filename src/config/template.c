/* Compiled variable templates: see template.h for the syntax and the contracts. */
#include "config/template.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef BST_TEST
int bst_tpl_test_fail_alloc;
size_t bst_tpl_test_alloc_req;
#endif

/* ---- Registry ---- */

typedef struct reg_ent {
	const char *name; /* owned copy */
	size_t len;
	bst_var_fn fn;
	bool prefix;
} reg_ent;

struct bst_var_reg {
	reg_ent *e;
	size_t n, cap;
};

#define VAR_NAME_MAX 64

extern const bst_vartab *const __start_bst_vars[] __attribute__((weak));
extern const bst_vartab *const __stop_bst_vars[] __attribute__((weak));

const bst_vartab *const *bst_vartabs(size_t *n)
{
	if (__start_bst_vars == NULL || __stop_bst_vars == NULL) {
		*n = 0;
		return NULL;
	}
	*n = (size_t)(__stop_bst_vars - __start_bst_vars);
	return __start_bst_vars;
}

bst_var_reg *bst_var_reg_new(void)
{
	return calloc(1, sizeof(bst_var_reg));
}

void bst_var_reg_free(bst_var_reg *r)
{
	if (r == NULL)
		return;
	for (size_t i = 0; i < r->n; i++)
		free((void *)(uintptr_t)r->e[i].name);
	free(r->e);
	free(r);
}

static bool ident_start(unsigned char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}
static bool ident_char(unsigned char c)
{
	return ident_start(c) || (c >= '0' && c <= '9');
}

static bool name_ok(const char *s, size_t n, bool prefix)
{
	if (n == 0 || n > VAR_NAME_MAX)
		return false;
	if (!prefix && n == 1 && s[0] >= '1' && s[0] <= '9')
		return true; /* captures */
	if (!ident_start((unsigned char)s[0]))
		return false;
	for (size_t i = 1; i < n; i++)
		if (!ident_char((unsigned char)s[i]))
			return false;
	return true;
}

static int reg_add(bst_var_reg *r, const char *name, bst_var_fn fn, bool prefix, bst_err *err)
{
	size_t n = name ? strlen(name) : 0;
	if (r == NULL || fn == NULL || !name_ok(name, n, prefix)) {
		bst_err_set(err, "invalid variable %s \"%.*s\"", prefix ? "prefix" : "name",
			    (int)(n > VAR_NAME_MAX ? VAR_NAME_MAX : n), name ? name : "");
		return -1;
	}
	for (size_t i = 0; i < r->n; i++) {
		const reg_ent *o = &r->e[i];
		if (!o->prefix && !prefix && o->len == n && memcmp(o->name, name, n) == 0) {
			bst_err_set(err, "duplicate variable \"$%s\"", name);
			return -1;
		}
		if (!o->prefix && !prefix)
			continue;
		/* a prefix against anything: one name starting with the other is ambiguous */
		size_t m = o->len < n ? o->len : n;
		if (memcmp(o->name, name, m) == 0) {
			bst_err_set(err, "variable %s \"%s\" collides with %s \"%s\"",
				    prefix ? "prefix" : "name", name,
				    o->prefix ? "prefix" : "name", o->name);
			return -1;
		}
	}
	if (r->n == r->cap) {
		size_t nc = r->cap ? r->cap * 2 : 16;
		reg_ent *ne = realloc(r->e, nc * sizeof *ne);
		if (ne == NULL) {
			bst_err_set(err, "out of memory registering variables");
			return -1;
		}
		r->e = ne;
		r->cap = nc;
	}
	char *cp = malloc(n + 1);
	if (cp == NULL) {
		bst_err_set(err, "out of memory registering variables");
		return -1;
	}
	memcpy(cp, name, n + 1);
	r->e[r->n++] = (reg_ent){ cp, n, fn, prefix };
	return 0;
}

int bst_var_register(bst_var_reg *r, const char *name, bst_var_fn fn, bst_err *err)
{
	return reg_add(r, name, fn, false, err);
}

int bst_var_register_prefix(bst_var_reg *r, const char *prefix, bst_var_fn fn, bst_err *err)
{
	return reg_add(r, prefix, fn, true, err);
}

bst_var_reg *bst_var_reg_build(const bst_vartab *const *tabs, size_t n, bst_err *err)
{
	bst_var_reg *r = bst_var_reg_new();
	if (r == NULL) {
		bst_err_set(err, "out of memory registering variables");
		return NULL;
	}
	for (size_t i = 0; i < n; i++) {
		if (tabs[i] == NULL)
			continue;
		for (size_t j = 0; j < tabs[i]->n; j++) {
			const bst_var_def *d = &tabs[i]->defs[j];
			if (reg_add(r, d->name, d->fn, d->prefix, err) != 0) {
				bst_var_reg_free(r);
				return NULL;
			}
		}
	}
	return r;
}

static pthread_once_t real_once = PTHREAD_ONCE_INIT;
static bst_var_reg *real_reg;
static bst_err real_err;

static void real_init(void)
{
	size_t n;
	const bst_vartab *const *tabs = bst_vartabs(&n);
	real_reg = bst_var_reg_build(tabs, n, &real_err);
}

const bst_var_reg *bst_var_registry(bst_err *err)
{
	pthread_once(&real_once, real_init);
	if (real_reg == NULL && err != NULL)
		*err = real_err;
	return real_reg;
}

/* Exact name first, then a prefix with a non-empty suffix. *suffix_off is where the
 * suffix starts. NULL when nothing matches; *empty_suffix is set for a bare prefix. */
static const reg_ent *reg_find(const bst_var_reg *r, const char *s, size_t n, size_t *suffix_off,
			       bool *empty_suffix)
{
	*empty_suffix = false;
	for (size_t i = 0; i < r->n; i++) {
		const reg_ent *o = &r->e[i];
		if (o->prefix || o->len != n || memcmp(o->name, s, n) != 0)
			continue;
		*suffix_off = n;
		return o;
	}
	for (size_t i = 0; i < r->n; i++) {
		const reg_ent *o = &r->e[i];
		if (!o->prefix || n < o->len || memcmp(o->name, s, o->len) != 0)
			continue;
		if (n == o->len) {
			*empty_suffix = true;
			return NULL;
		}
		*suffix_off = o->len;
		return o;
	}
	return NULL;
}

/* ---- Compile ---- */

typedef struct tpl_op {
	bst_var_fn fn;	 /* NULL: literal */
	const char *p;	 /* literal text, or the variable's suffix */
	uint32_t len;
} tpl_op;

struct bst_tpl {
	const tpl_op *ops;
	uint32_t n;
};

/* The header type is the same layout under a different, incompatible C type. */
struct bst_header_tpl {
	struct bst_tpl t;
};

/* RFC 9110 field-value: control bytes except HTAB, and DEL. */
static bool unsafe_byte(unsigned char c)
{
	return (c < 0x20 && c != '\t') || c == 0x7f;
}

static bool has_unsafe(const char *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (unsafe_byte((unsigned char)p[i]))
			return true;
	return false;
}

typedef struct cstate {
	const bst_loc *loc;
	bst_err *err;
} cstate;

static void fail(const cstate *cs, size_t off, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));
static void fail(const cstate *cs, size_t off, const char *fmt, ...)
{
	char m[200];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(m, sizeof m, fmt, ap);
	va_end(ap);
	if (cs->err == NULL)
		return;
	if (cs->loc != NULL) {
		bst_err_set(cs->err, "%s (at byte %zu of the template)", m, off);
		cs->err->file = cs->loc->file;
		cs->err->line = cs->loc->line;
		cs->err->col = cs->loc->col;
	} else {
		bst_err_set(cs->err, "%s", m);
		cs->err->line = 1;
		cs->err->col = (off + 1 > (size_t)INT32_MAX) ? INT32_MAX : (int)(off + 1);
	}
}

static bst_tpl *compile_core(const bst_var_reg *r, bst_str s, const bst_loc *loc, bool header,
			     bst_arena *a, bst_err *err)
{
	cstate cs = { loc, err };
	const char *in = s.p;
	size_t n = s.len;
	if (r == NULL || (in == NULL && n != 0)) {
		bst_err_set(err, "no variable registry");
		return NULL;
	}
	tpl_op ops[BST_TPL_MAX_OPS];
	size_t nops = 0;
	/* Literals and suffixes never exceed the input in total, so one buffer fits all. */
	char *buf = bst_arena_alloc(a, n ? n : 1);
	if (buf == NULL) {
		bst_err_set(err, "out of memory compiling a template");
		return NULL;
	}
	size_t w = 0, lit_start = 0;

#define FLUSH_LIT()                                                                     \
	do {                                                                            \
		if (w > lit_start) {                                                    \
			if (nops == BST_TPL_MAX_OPS)                                    \
				goto too_big;                                           \
			ops[nops++] = (tpl_op){ NULL, buf + lit_start,                  \
						(uint32_t)(w - lit_start) };            \
		}                                                                       \
	} while (0)

	for (size_t i = 0; i < n;) {
		unsigned char c = (unsigned char)in[i];
		if (c == '\\' && i + 1 < n && in[i + 1] == '$') {
			buf[w++] = '$';
			i += 2;
			continue;
		}
		if (c != '$') {
			if (header && unsafe_byte(c)) {
				fail(&cs, i, "a header value may not contain CR, LF, NUL or other "
					     "control bytes (a \"\\n\" escape in the literal text)");
				return NULL;
			}
			buf[w++] = (char)c;
			i++;
			continue;
		}
		size_t dollar = i;
		if (i + 1 >= n) {
			fail(&cs, dollar, "a lone \"$\" at the end of the template: write $$ for a "
					  "literal dollar");
			return NULL;
		}
		unsigned char d = (unsigned char)in[i + 1];
		if (d == '$') {
			buf[w++] = '$';
			i += 2;
			continue;
		}
		if (d == '{') {
			fail(&cs, dollar, "\"${\" is not a template variable: environment expansion "
					  "runs earlier, before templates; use $name here, or $$ "
					  "for a literal dollar");
			return NULL;
		}
		size_t ns, ne;
		if (d == '0') {
			fail(&cs, dollar, "$0 is not a variable: regex captures are $1 to $9");
			return NULL;
		} else if (d >= '1' && d <= '9') {
			ns = i + 1;
			ne = i + 2; /* one digit only: $10 is $1 then "0" */
		} else if (ident_start(d)) {
			ns = i + 1;
			ne = ns + 1;
			while (ne < n && ident_char((unsigned char)in[ne]))
				ne++;
		} else {
			fail(&cs, dollar, "\"$\" must be followed by a variable name, \"$\" or a "
					  "digit 1-9; write $$ for a literal dollar");
			return NULL;
		}
		size_t nlen = ne - ns, off = 0;
		bool bare = false;
		const reg_ent *ent = reg_find(r, in + ns, nlen, &off, &bare);
		if (ent == NULL) {
			if (bare)
				fail(&cs, dollar, "variable \"$%.*s\" needs a name after the prefix",
				     (int)(nlen > 60 ? 60 : nlen), in + ns);
			else
				fail(&cs, dollar, "unknown variable \"$%.*s\"",
				     (int)(nlen > 60 ? 60 : nlen), in + ns);
			return NULL;
		}
		FLUSH_LIT();
		if (nops == BST_TPL_MAX_OPS)
			goto too_big;
		size_t sl = nlen - off;
		ops[nops++] = (tpl_op){ ent->fn, buf + w, (uint32_t)sl };
		memcpy(buf + w, in + ns + off, sl);
		w += sl;
		lit_start = w;
		i = ne;
	}
	FLUSH_LIT();
#undef FLUSH_LIT

	{
		bst_tpl *t = bst_arena_alloc(a, sizeof *t);
		tpl_op *o = bst_arena_alloc(a, (nops ? nops : 1) * sizeof *o);
		if (t == NULL || o == NULL) {
			bst_err_set(err, "out of memory compiling a template");
			return NULL;
		}
		if (nops)
			memcpy(o, ops, nops * sizeof *o);
		t->ops = o;
		t->n = (uint32_t)nops;
		return t;
	}
too_big:
	fail(&cs, 0, "template is too complex: more than %d literal and variable parts", BST_TPL_MAX_OPS);
	return NULL;
}

bst_tpl *bst_tpl_compile_with(const bst_var_reg *r, bst_str s, const bst_loc *loc,
			      bst_arena *a, bst_err *err)
{
	return compile_core(r, s, loc, false, a, err);
}

bst_header_tpl *bst_tpl_compile_header_with(const bst_var_reg *r, bst_str s, const bst_loc *loc,
					    bst_arena *a, bst_err *err)
{
	return (bst_header_tpl *)compile_core(r, s, loc, true, a, err);
}

bst_tpl *bst_tpl_compile(bst_str s, bst_arena *a, bst_err *err)
{
	const bst_var_reg *r = bst_var_registry(err);
	return r ? compile_core(r, s, NULL, false, a, err) : NULL;
}

bst_header_tpl *bst_tpl_compile_header(bst_str s, bst_arena *a, bst_err *err)
{
	const bst_var_reg *r = bst_var_registry(err);
	return r ? (bst_header_tpl *)compile_core(r, s, NULL, true, a, err) : NULL;
}

static bst_tpl *arg_core(const bst_ast_arg *arg, bool header, bst_arena *a, bst_err *err)
{
	const bst_var_reg *r = bst_var_registry(err);
	if (r == NULL)
		return NULL;
	if (arg->tpl_len > UINT32_MAX) {
		bst_err_set(err, "template too long");
		return NULL;
	}
	return compile_core(r, (bst_str){ arg->tpl, (uint32_t)arg->tpl_len }, &arg->loc, header, a,
			    err);
}

bst_tpl *bst_tpl_compile_arg(const bst_ast_arg *arg, bst_arena *a, bst_err *err)
{
	return arg_core(arg, false, a, err);
}

bst_header_tpl *bst_tpl_compile_header_arg(const bst_ast_arg *arg, bst_arena *a, bst_err *err)
{
	return (bst_header_tpl *)arg_core(arg, true, a, err);
}

bool bst_tpl_var_known(const char *name)
{
	const bst_var_reg *r = bst_var_registry(NULL);
	size_t off;
	bool bare;
	return r != NULL && reg_find(r, name, strlen(name), &off, &bare) != NULL;
}

int bst_tpl_check_arg(const bst_ast_arg *arg, bst_err *err)
{
	bst_arena *tmp = bst_arena_new(1 << 12);
	if (tmp == NULL) {
		bst_err_set(err, "out of memory checking a template");
		return -1;
	}
	int rc = arg_core(arg, false, tmp, err) ? 0 : -1;
	bst_arena_free(tmp);
	return rc;
}

bst_var_fn bst_tpl_first_var(const bst_tpl *t)
{
	return t->n > 0 ? t->ops[0].fn : NULL;
}

bst_var_fn bst_header_tpl_first_var(const bst_header_tpl *t)
{
	return bst_tpl_first_var(&t->t);
}

/* ---- Eval ---- */

bool bst_tpl_is_literal(const bst_tpl *t)
{
	return t->n == 0 || (t->n == 1 && t->ops[0].fn == NULL);
}

static bst_str empty_ok(void)
{
	return (bst_str){ "", 0 };
}

/* Computes every part once. Returns BST_TPL_OK with *out set (no copy for a literal or a
 * single variable, one arena allocation otherwise), or BST_TPL_FAIL. When scan, a value
 * with a forbidden byte gives BST_TPL_UNSAFE before anything is allocated. */
static int eval_core(const bst_tpl *t, const bst_var_ctx *ctx, bst_arena *a, bool scan,
		     bst_str *out)
{
	if (t->n == 0) {
		*out = empty_ok();
		return BST_TPL_OK;
	}
	if (t->n == 1 && t->ops[0].fn == NULL) { /* literal only: no allocation, no copy */
		*out = (bst_str){ t->ops[0].p, t->ops[0].len };
		return BST_TPL_OK;
	}
	bst_str vals[BST_TPL_MAX_OPS];
	size_t total = 0;
	for (uint32_t i = 0; i < t->n; i++) {
		const tpl_op *o = &t->ops[i];
		bst_str v = o->fn ? o->fn(ctx, (bst_str){ o->p, o->len })
				  : (bst_str){ o->p, o->len };
		if (v.p == NULL)
			v.len = 0;
		vals[i] = v;
		if ((size_t)v.len > SIZE_MAX - total)
			return BST_TPL_FAIL;
		total += v.len;
		if (total > UINT32_MAX)
			return BST_TPL_FAIL;
	}
	if (scan) { /* literals were vetted at compile; only values can carry bytes */
		for (uint32_t i = 0; i < t->n; i++)
			if (t->ops[i].fn != NULL && has_unsafe(vals[i].p, vals[i].len))
				return BST_TPL_UNSAFE;
	}
	if (total == 0) {
		*out = empty_ok();
		return BST_TPL_OK;
	}
	if (t->n == 1) { /* a single variable: its own bytes, no copy */
		*out = vals[0];
		return BST_TPL_OK;
	}
	char *buf = NULL;
#ifdef BST_TEST
	bst_tpl_test_alloc_req = total;
	if (!bst_tpl_test_fail_alloc)
#endif
		buf = a ? bst_arena_alloc(a, total) : NULL;
	if (buf == NULL)
		return BST_TPL_FAIL;
	size_t w = 0;
	for (uint32_t i = 0; i < t->n; i++) {
		if (vals[i].len)
			memcpy(buf + w, vals[i].p, vals[i].len);
		w += vals[i].len;
	}
	*out = (bst_str){ buf, (uint32_t)total };
	return BST_TPL_OK;
}

bst_str bst_tpl_eval(const bst_tpl *t, const bst_var_ctx *ctx, bst_arena *a)
{
	bst_str out;
	if (eval_core(t, ctx, a, false, &out) != BST_TPL_OK)
		return (bst_str){ NULL, 0 };
	return out;
}

int bst_header_tpl_eval(const bst_header_tpl *t, const bst_var_ctx *ctx, bst_arena *a,
			bst_str *out)
{
	int rc = eval_core(&t->t, ctx, a, true, out);
	if (rc != BST_TPL_OK)
		*out = empty_ok();
	return rc;
}
