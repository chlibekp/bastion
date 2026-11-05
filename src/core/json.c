#include "core/json.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "core/hash.h"

/* Tests replace the random source to prove a failure fails the parse. */
#ifdef BST_TEST
ssize_t (*bst_json_getrandom_hook)(void *, size_t, unsigned) = NULL;
#endif
static ssize_t bst_getrandom_(void *buf, size_t n, unsigned flags)
{
#ifdef BST_TEST
	if (bst_json_getrandom_hook != NULL)
		return bst_json_getrandom_hook(buf, n, flags);
#endif
	return getrandom(buf, n, flags);
}

struct bst_json {
	uint8_t type;
	bool b;
	uint32_t n;           /* element or member count */
	bst_str s;            /* string value, or verbatim number text */
	bst_str key;          /* member key when this node is an object member's value */
	bst_json **items;     /* array elements or object member values */
	bst_json *next;       /* build-time chain, unused once the container is closed */
};

#define SMALL_OBJ 8       /* up to this many members: pairwise duplicate check */
#define EXP_SAT ((int64_t)1 << 40)  /* above any digit count (len < 2^32), so it never cancels */

#include "core/json_utf8.h"

/* ---- parser ---- */

typedef struct ctx {
	bst_arena *a;
	const unsigned char *s;
	size_t len;
	size_t pos;
	bst_err *err;
	uint8_t hkey[16];
	bool have_hkey;
} ctx;

/* Reports at byte offset off. msg must be a fixed string: input bytes never enter it. */
static void fail_at(ctx *c, size_t off, const char *msg)
{
	if (!c->err)
		return;
	int line = 1, col = 1;
	for (size_t i = 0; i < off && i < c->len; i++) {
		if (c->s[i] == '\n') {
			line++;
			col = 1;
		} else if (col < INT32_MAX) {
			col++;
		}
	}
	bst_err_set(c->err, "json: %s (line %d, column %d)", msg, line, col);
	c->err->line = line;
	c->err->col = col;
}

#define FAIL(c, msg) (fail_at((c), (c)->pos, (msg)), NULL)

static bst_json *node_new(ctx *c, bst_json_type t)
{
	bst_json *j = bst_arena_alloc(c->a, sizeof *j);
	if (!j)
		return FAIL(c, "out of memory");
	memset(j, 0, sizeof *j);
	j->type = (uint8_t)t;
	return j;
}

static void skip_ws(ctx *c)
{
	while (c->pos < c->len) {
		unsigned char ch = c->s[c->pos];
		if (ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r')
			break;
		c->pos++;
	}
}

static int hexval(unsigned char ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	return -1;
}

static bool hex4(ctx *c, size_t at, uint32_t *out)
{
	if (c->len - at < 4)
		return false;
	uint32_t v = 0;
	for (size_t i = 0; i < 4; i++) {
		int h = hexval(c->s[at + i]);
		if (h < 0)
			return false;
		v = (v << 4) | (uint32_t)h;
	}
	*out = v;
	return true;
}

/* pos is at the opening quote. On success fills *out (NUL-terminated copy in the arena)
 * and leaves pos after the closing quote. */
static bool parse_string(ctx *c, bst_str *out)
{
	size_t i = c->pos + 1, start = i;
	while (i < c->len && c->s[i] != '"') {
		unsigned char ch = c->s[i];
		if (ch < 0x20) {
			c->pos = i;
			fail_at(c, i, "control character in string");
			return false;
		}
		i += (ch == '\\') ? 2 : 1;
	}
	if (i >= c->len) {
		c->pos = c->len;
		fail_at(c, c->len, "unterminated string");
		return false;
	}
	size_t end = i, raw = end - start;
	/* Decoded form is never longer than the source (\uXXXX: 6 -> <=3, pair: 12 -> 4). */
	unsigned char *o = bst_arena_alloc(c->a, raw + 1);
	if (!o) {
		fail_at(c, c->pos, "out of memory");
		return false;
	}
	size_t n = 0;
	i = start;
	while (i < end) {
		unsigned char ch = c->s[i];
		if (ch == '\\') {
			if (i + 1 >= end) {
				fail_at(c, i, "bad escape");
				return false;
			}
			unsigned char e = c->s[i + 1];
			size_t esc_at = i;
			i += 2;
			switch (e) {
			case '"': o[n++] = '"'; break;
			case '\\': o[n++] = '\\'; break;
			case '/': o[n++] = '/'; break;
			case 'b': o[n++] = '\b'; break;
			case 'f': o[n++] = '\f'; break;
			case 'n': o[n++] = '\n'; break;
			case 'r': o[n++] = '\r'; break;
			case 't': o[n++] = '\t'; break;
			case 'u': {
				uint32_t cp;
				if (i + 4 > end || !hex4(c, i, &cp)) {
					fail_at(c, esc_at, "bad \\u escape");
					return false;
				}
				i += 4;
				if (cp >= 0xd800 && cp <= 0xdbff) {
					uint32_t lo;
					if (i + 6 > end || c->s[i] != '\\' || c->s[i + 1] != 'u' ||
					    !hex4(c, i + 2, &lo) || lo < 0xdc00 || lo > 0xdfff) {
						fail_at(c, esc_at, "lone high surrogate");
						return false;
					}
					i += 6;
					cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
				} else if (cp >= 0xdc00 && cp <= 0xdfff) {
					fail_at(c, esc_at, "lone low surrogate");
					return false;
				} else if (cp == 0) {
					fail_at(c, esc_at, "U+0000 not allowed in strings");
					return false;
				}
				n += utf8_put(o + n, cp);
				break;
			}
			default:
				fail_at(c, esc_at, "bad escape");
				return false;
			}
		} else if (ch < 0x80) {
			o[n++] = ch;
			i++;
		} else {
			uint32_t cp;
			size_t k = utf8_next(c->s + i, c->s + end, &cp);
			if (k == 0) {
				fail_at(c, i, "invalid UTF-8");
				return false;
			}
			memcpy(o + n, c->s + i, k);
			n += k;
			i += k;
		}
	}
	o[n] = '\0';
	out->p = (const char *)o;
	out->len = (uint32_t)n;
	c->pos = end + 1;
	return true;
}

static bst_json *parse_number(ctx *c)
{
	size_t i = c->pos;
	const unsigned char *s = c->s;
	size_t len = c->len;
	if (i < len && s[i] == '-')
		i++;
	if (i >= len || s[i] < '0' || s[i] > '9')
		return fail_at(c, i, "bad number"), NULL;
	if (s[i] == '0') {
		i++;
	} else {
		while (i < len && s[i] >= '0' && s[i] <= '9')
			i++;
	}
	if (i < len && s[i] == '.') {
		i++;
		if (i >= len || s[i] < '0' || s[i] > '9')
			return fail_at(c, i, "bad number"), NULL;
		while (i < len && s[i] >= '0' && s[i] <= '9')
			i++;
	}
	if (i < len && (s[i] == 'e' || s[i] == 'E')) {
		i++;
		if (i < len && (s[i] == '+' || s[i] == '-'))
			i++;
		if (i >= len || s[i] < '0' || s[i] > '9')
			return fail_at(c, i, "bad number"), NULL;
		while (i < len && s[i] >= '0' && s[i] <= '9')
			i++;
	}
	bst_json *j = node_new(c, BST_JSON_NUM);
	if (!j)
		return NULL;
	size_t n = i - c->pos;
	char *copy = bst_arena_alloc(c->a, n + 1);
	if (!copy)
		return FAIL(c, "out of memory");
	memcpy(copy, s + c->pos, n);
	copy[n] = '\0';
	j->s.p = copy;
	j->s.len = (uint32_t)n;
	c->pos = i;
	return j;
}

static bst_json *parse_value(ctx *c, int depth);

static bst_json *parse_literal(ctx *c, const char *lit, size_t n, bst_json_type t, bool b)
{
	if (c->len - c->pos < n || memcmp(c->s + c->pos, lit, n) != 0)
		return FAIL(c, "unexpected token");
	bst_json *j = node_new(c, t);
	if (!j)
		return NULL;
	j->b = b;
	c->pos += n;
	return j;
}

static bool key_eq(bst_str a, bst_str b)
{
	return a.len == b.len && memcmp(a.p, b.p, a.len) == 0;
}

/* Returns false if two members share a key. Allocation failure also returns false,
 * with *oom set and *why naming the reason. */
static bool keys_unique(ctx *c, bst_json **m, size_t n, bool *oom, const char **why)
{
	*oom = false;
	*why = "out of memory";
	if (n <= SMALL_OBJ) {
		for (size_t i = 1; i < n; i++)
			for (size_t k = 0; k < i; k++)
				if (key_eq(m[i]->key, m[k]->key))
					return false;
		return true;
	}
	if (!c->have_hkey) {
		/* No fallback: a key derived from addresses is guessable, and a guessable key
		 * lets an attacker force hash collisions. Fail the parse instead. */
		if (bst_getrandom_(c->hkey, sizeof c->hkey, GRND_NONBLOCK) != (ssize_t)sizeof c->hkey) {
			*oom = true;
			*why = "no random bytes for the object hash key";
			return false;
		}
		c->have_hkey = true;
	}
	size_t cap = 16;
	while (cap < n * 2) {
		if (cap > SIZE_MAX / 2 / sizeof(bst_json *)) {
			*oom = true;
			return false;
		}
		cap <<= 1;
	}
	bst_json **tab = bst_arena_alloc(c->a, cap * sizeof *tab);
	if (!tab) {
		*oom = true;
		return false;
	}
	memset(tab, 0, cap * sizeof *tab);
	for (size_t i = 0; i < n; i++) {
		uint64_t h = bst_siphash13(c->hkey, m[i]->key.p, m[i]->key.len);
		size_t slot = (size_t)h & (cap - 1);
		while (tab[slot]) {
			if (key_eq(tab[slot]->key, m[i]->key))
				return false;
			slot = (slot + 1) & (cap - 1);
		}
		tab[slot] = m[i];
	}
	return true;
}

/* Turns the build-time chain into the items array. */
static bool flatten(ctx *c, bst_json *j, bst_json *head, size_t n)
{
	j->n = (uint32_t)n;
	if (n == 0)
		return true;
	if (n > SIZE_MAX / sizeof(bst_json *))
		return false;
	j->items = bst_arena_alloc(c->a, n * sizeof(bst_json *));
	if (!j->items)
		return false;
	size_t i = 0;
	for (bst_json *e = head; e; e = e->next)
		j->items[i++] = e;
	return true;
}

static bst_json *parse_array(ctx *c, int depth)
{
	bst_json *j = node_new(c, BST_JSON_ARR);
	if (!j)
		return NULL;
	c->pos++; /* [ */
	skip_ws(c);
	bst_json *head = NULL, *tail = NULL;
	size_t n = 0;
	if (c->pos < c->len && c->s[c->pos] == ']') {
		c->pos++;
		return j;
	}
	for (;;) {
		bst_json *v = parse_value(c, depth);
		if (!v)
			return NULL;
		if (n >= UINT32_MAX - 1)
			return FAIL(c, "too many elements");
		if (tail)
			tail->next = v;
		else
			head = v;
		tail = v;
		n++;
		skip_ws(c);
		if (c->pos >= c->len)
			return FAIL(c, "unterminated array");
		if (c->s[c->pos] == ',') {
			c->pos++;
			continue;
		}
		if (c->s[c->pos] == ']') {
			c->pos++;
			break;
		}
		return FAIL(c, "expected ',' or ']'");
	}
	if (!flatten(c, j, head, n))
		return FAIL(c, "out of memory");
	return j;
}

static bst_json *parse_object(ctx *c, int depth)
{
	bst_json *j = node_new(c, BST_JSON_OBJ);
	if (!j)
		return NULL;
	c->pos++; /* { */
	skip_ws(c);
	bst_json *head = NULL, *tail = NULL;
	size_t n = 0;
	if (c->pos < c->len && c->s[c->pos] == '}') {
		c->pos++;
		return j;
	}
	for (;;) {
		skip_ws(c);
		if (c->pos >= c->len || c->s[c->pos] != '"')
			return FAIL(c, "expected object key");
		bst_str key;
		if (!parse_string(c, &key))
			return NULL;
		skip_ws(c);
		if (c->pos >= c->len || c->s[c->pos] != ':')
			return FAIL(c, "expected ':'");
		c->pos++;
		bst_json *v = parse_value(c, depth);
		if (!v)
			return NULL;
		if (n >= UINT32_MAX - 1)
			return FAIL(c, "too many members");
		v->key = key;
		if (tail)
			tail->next = v;
		else
			head = v;
		tail = v;
		n++;
		skip_ws(c);
		if (c->pos >= c->len)
			return FAIL(c, "unterminated object");
		if (c->s[c->pos] == ',') {
			c->pos++;
			continue;
		}
		if (c->s[c->pos] == '}') {
			c->pos++;
			break;
		}
		return FAIL(c, "expected ',' or '}'");
	}
	if (!flatten(c, j, head, n))
		return FAIL(c, "out of memory");
	bool oom;
	const char *why;
	if (!keys_unique(c, j->items, n, &oom, &why))
		return FAIL(c, oom ? why : "duplicate object key");
	return j;
}

/* depth is the number of containers already open around this value. */
static bst_json *parse_value(ctx *c, int depth)
{
	skip_ws(c);
	if (c->pos >= c->len)
		return FAIL(c, "unexpected end of input");
	unsigned char ch = c->s[c->pos];
	switch (ch) {
	case '{':
	case '[':
		if (depth >= BST_JSON_MAX_DEPTH)
			return FAIL(c, "nesting too deep");
		return ch == '{' ? parse_object(c, depth + 1) : parse_array(c, depth + 1);
	case '"': {
		bst_json *j = node_new(c, BST_JSON_STR);
		if (!j || !parse_string(c, &j->s))
			return NULL;
		return j;
	}
	case 't':
		return parse_literal(c, "true", 4, BST_JSON_BOOL, true);
	case 'f':
		return parse_literal(c, "false", 5, BST_JSON_BOOL, false);
	case 'n':
		return parse_literal(c, "null", 4, BST_JSON_NULL, false);
	default:
		if (ch == '-' || (ch >= '0' && ch <= '9'))
			return parse_number(c);
		return FAIL(c, "unexpected character");
	}
}

bst_json *bst_json_parse(bst_arena *a, const char *s, size_t len, bst_err *err)
{
	ctx c = { .a = a, .s = (const unsigned char *)s, .len = len, .err = err };
	if (!a || (!s && len > 0) || len >= UINT32_MAX) {
		bst_err_set(err, "json: invalid input");
		return NULL;
	}
	bst_json *j = parse_value(&c, 0);
	if (!j)
		return NULL;
	skip_ws(&c);
	if (c.pos != c.len)
		return FAIL(&c, "trailing content after value");
	return j;
}

/* ---- accessors ---- */

bst_json_type bst_json_typeof(const bst_json *j)
{
	return j ? (bst_json_type)j->type : BST_JSON_NULL;
}

bool bst_json_bool(const bst_json *j, bool *out)
{
	if (!j || j->type != BST_JSON_BOOL)
		return false;
	*out = j->b;
	return true;
}

bool bst_json_str(const bst_json *j, bst_str *out)
{
	if (!j || j->type != BST_JSON_STR)
		return false;
	*out = j->s;
	return true;
}

bool bst_json_num_text(const bst_json *j, bst_str *out)
{
	if (!j || j->type != BST_JSON_NUM)
		return false;
	*out = j->s;
	return true;
}

bst_json_int_rc bst_json_int(const bst_json *j, int64_t *out)
{
	if (!j || j->type != BST_JSON_NUM)
		return BST_JSON_INT_NOT_NUMBER;
	const char *p = j->s.p, *end = p + j->s.len;
	bool neg = false;
	if (p < end && *p == '-') {
		neg = true;
		p++;
	}
	/* Collect significant digits of mantissa (integer and fraction) as a decimal
	 * string d x 10^e10. Leading zeros are dropped, trailing zeros folded into e10. */
	const char *dig[2] = { NULL, NULL };
	size_t dlen[2] = { 0, 0 };
	dig[0] = p;
	while (p < end && *p >= '0' && *p <= '9')
		p++;
	dlen[0] = (size_t)(p - dig[0]);
	if (p < end && *p == '.') {
		p++;
		dig[1] = p;
		while (p < end && *p >= '0' && *p <= '9')
			p++;
		dlen[1] = (size_t)(p - dig[1]);
	}
	int64_t exp = 0;
	if (p < end && (*p == 'e' || *p == 'E')) {
		p++;
		bool eneg = false;
		if (p < end && (*p == '+' || *p == '-'))
			eneg = *p++ == '-';
		while (p < end) {
			if (exp < EXP_SAT)
				exp = exp * 10 + (*p - '0');
			if (exp > EXP_SAT)
				exp = EXP_SAT;
			p++;
		}
		if (eneg)
			exp = -exp;
	}
	int64_t e10 = exp - (int64_t)dlen[1];
	/* The mantissa digits are dig[0][0..dlen[0]) followed by dig[1][0..dlen[1]). */
	size_t total = dlen[0] + dlen[1];
	size_t lead = 0;
	while (lead < total) {
		char ch = lead < dlen[0] ? dig[0][lead] : dig[1][lead - dlen[0]];
		if (ch != '0')
			break;
		lead++;
	}
	if (lead == total) {
		*out = 0; /* zero, including -0 */
		return BST_JSON_INT_OK;
	}
	while (total > lead) {
		size_t k = total - 1;
		char ch = k < dlen[0] ? dig[0][k] : dig[1][k - dlen[0]];
		if (ch != '0')
			break;
		total--;
		e10++;
	}
	if (e10 < 0)
		return BST_JSON_INT_NOT_INTEGER;
	size_t nd = total - lead;
	if (nd > 16 || e10 > 16 || (int64_t)nd + e10 > 16)
		return BST_JSON_INT_RANGE;
	uint64_t v = 0;
	for (size_t k = lead; k < total; k++) {
		char ch = k < dlen[0] ? dig[0][k] : dig[1][k - dlen[0]];
		v = v * 10 + (uint64_t)(ch - '0');
	}
	for (int64_t i = 0; i < e10; i++)
		v *= 10;
	if (v > ((uint64_t)1 << 53) - 1)
		return BST_JSON_INT_RANGE;
	*out = neg ? -(int64_t)v : (int64_t)v;
	return BST_JSON_INT_OK;
}

const bst_json *bst_json_get(const bst_json *obj, const char *key)
{
	if (!obj || obj->type != BST_JSON_OBJ || !key)
		return NULL;
	size_t kl = strlen(key);
	for (uint32_t i = 0; i < obj->n; i++) {
		const bst_json *m = obj->items[i];
		if (m->key.len == kl && memcmp(m->key.p, key, kl) == 0)
			return m;
	}
	return NULL;
}

size_t bst_json_arr_len(const bst_json *arr)
{
	if (!arr || (arr->type != BST_JSON_ARR && arr->type != BST_JSON_OBJ))
		return 0;
	return arr->n;
}

const bst_json *bst_json_arr_at(const bst_json *arr, size_t i)
{
	if (!arr || arr->type != BST_JSON_ARR || i >= arr->n)
		return NULL;
	return arr->items[i];
}

const bst_json *bst_json_obj_at(const bst_json *obj, size_t i, bst_str *key)
{
	if (!obj || obj->type != BST_JSON_OBJ || i >= obj->n)
		return NULL;
	if (key)
		*key = obj->items[i]->key;
	return obj->items[i];
}
