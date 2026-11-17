/* `compress` and its companions (filters/compress.h): which responses are compressed on the fly,
 * with what and how hard. Every one inherits from global to server to location. */
#include "config/compile.h"
#include "config/values.h"
#include "core/str.h"
#include "http/accept_encoding.h"

#include <ctype.h>
#include <string.h>

#define UP1(...) .args = { .min_args = 1, .max_args = 1, .pos = { __VA_ARGS__ } }
#define ANY_ARGS(...) .args = { .min_args = 1, .max_args = BST_ARGS_ANY, .pos = { __VA_ARGS__ } }
#define GSL (BST_CTX_GLOBAL | BST_CTX_SERVER | BST_CTX_LOCATION)

static bst_str as_str(const bst_ast_arg *a)
{
	return (bst_str){ a->text, (uint32_t)a->len };
}

static int64_t arg_int(const bst_directive *d, const bst_ast_node *n)
{
	int64_t v = 0;
	(void)bst_parse_int(as_str(bst_dir_pos(d, n, 0)), INT32_MIN, INT32_MAX, &v);
	return v;
}

static int ap_compress(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	uint32_t m = 0;
	size_t np = bst_dir_npos(d, n);
	for (size_t i = 0; i < np; i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		bst_str v = as_str(a);
		if (bst_str_eq(v, BST_S("off"))) {
			if (np > 1) {
				bst_err_set(e, "compress: off stands alone");
				bst_cfg_err_at(e, &a->loc);
				return -1;
			}
		} else if (bst_str_eq(v, BST_S("zstd"))) {
			m |= BST_ENC_BIT(BST_ENC_ZSTD);
		} else if (bst_str_eq(v, BST_S("br"))) {
			m |= BST_ENC_BIT(BST_ENC_BR);
		} else if (bst_str_eq(v, BST_S("gzip"))) {
			m |= BST_ENC_BIT(BST_ENC_GZIP);
		}
	}
	c->common->compress.encodings = m;
	return 0;
}

static int ap_types(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	size_t np = bst_dir_npos(d, n);
	bst_str *v = bst_arena_alloc(c->arena, np * sizeof *v);
	if (v == NULL) {
		bst_err_set(e, "out of memory");
		return -1;
	}
	for (size_t i = 0; i < np; i++) {
		const bst_ast_arg *a = bst_dir_pos(d, n, i);
		char *t = bst_cfg_strdup(c, a->text, a->len, e);
		if (t == NULL)
			return -1;
		for (size_t k = 0; k < a->len; k++)
			t[k] = (char)tolower((unsigned char)t[k]);
		if (strchr(t, '/') == NULL) {
			bst_err_set(e, "compress_types: '%s' is not a media type (type/subtype)", t);
			bst_cfg_err_at(e, &a->loc);
			return -1;
		}
		v[i] = (bst_str){ t, (uint32_t)a->len };
	}
	c->common->compress.types = v;
	c->common->compress.ntypes = np;
	return 0;
}

static int ap_min_size(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	uint64_t v = 0;
	(void)bst_parse_size(as_str(bst_dir_pos(d, n, 0)), &v);
	c->common->compress.min_size = v;
	return 0;
}

#define AP_INT(fn, field, type)                                                              \
	static int fn(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e) \
	{                                                                                    \
		(void)e;                                                                     \
		c->common->compress.field = (type)arg_int(d, n);                             \
		return 0;                                                                    \
	}

AP_INT(ap_level_zstd, level_zstd, int)
AP_INT(ap_level_br, level_br, int)
AP_INT(ap_level_gzip, level_gzip, int)
AP_INT(ap_window, window, unsigned)
AP_INT(ap_max_concurrent, max_concurrent, unsigned)

static int ap_sensitive(bst_cfg_ctx *c, const bst_directive *d, const bst_ast_node *n, bst_err *e)
{
	(void)e;
	bool v = false;
	(void)bst_parse_bool(as_str(bst_dir_pos(d, n, 0)), &v);
	c->common->compress.sensitive = v;
	return 0;
}

static const char *const codings_v[] = { "zstd", "br", "gzip", "off", NULL };

static const bst_directive compress_dirs[] = {
	{ .name = "compress", .contexts = GSL, .apply = ap_compress, .default_value = "off",
	  .doc = "Compresses responses on the fly with the codings listed (zstd, br, gzip), choosing "
		 "by the client's Accept-Encoding (q-values first, then this server's order zstd, br, "
		 "gzip), or off. Applies to every handler and protocol. A response that is already "
		 "encoded, marked no-transform, answers a Range request, a HEAD, a 204 or a 304, is "
		 "smaller than compress_min_size or not of a compress_types type is sent as it is. A "
		 "compressed response loses Content-Length, gets Vary: Accept-Encoding and a weak "
		 "ETag.",
	  ANY_ARGS({ .kind = BST_T_ENUM, .enum_values = codings_v }) },
	{ .name = "compress_types", .contexts = GSL, .apply = ap_types,
	  .default_value = "text/html text/css text/plain text/javascript application/javascript "
			   "application/json application/xml image/svg+xml",
	  .doc = "Media types that are compressed, by the Content-Type without parameters; `text/*` "
		 "matches every text type. A response without Content-Type is not compressed.",
	  ANY_ARGS({ .kind = BST_T_STRING }) },
	{ .name = "compress_min_size", .contexts = GSL, .apply = ap_min_size, .default_value = "256",
	  .doc = "A response whose length is known and smaller than this is sent as it is: the "
		 "framing would cost more than it saves. A response of unknown length is compressed.",
	  UP1({ .kind = BST_T_SIZE, .min = 0 }) },
	{ .name = "compress_level_zstd", .contexts = GSL, .apply = ap_level_zstd, .default_value = "3",
	  .doc = "zstd level, 1 (fastest) to 19. The default favours speed.",
	  UP1({ .kind = BST_T_INT, .min = 1, .max = 19 }) },
	{ .name = "compress_level_br", .contexts = GSL, .apply = ap_level_br, .default_value = "4",
	  .doc = "Brotli quality, 0 to 11. Levels above 6 cost much CPU for little gain on the fly.",
	  UP1({ .kind = BST_T_INT, .min = 0, .max = 11 }) },
	{ .name = "compress_level_gzip", .contexts = GSL, .apply = ap_level_gzip, .default_value = "5",
	  .doc = "gzip level, 1 to 9.",
	  UP1({ .kind = BST_T_INT, .min = 1, .max = 9 }) },
	{ .name = "compress_window", .contexts = GSL, .apply = ap_window, .default_value = "15",
	  .doc = "log2 of the compression window in bytes (10 to 24): memory per stream against "
		 "ratio. gzip uses at most 15.",
	  UP1({ .kind = BST_T_INT, .min = 10, .max = 24 }) },
	{ .name = "compress_sensitive", .contexts = GSL, .apply = ap_sensitive, .default_value = "off",
	  .doc = "off: responses to requests with Cookie or Authorization, and responses that set "
		 "a cookie, are not compressed, because a secret reflected next to attacker-chosen "
		 "text in a compressed body leaks through its length (BREACH). on: compress them too.",
	  UP1({ .kind = BST_T_BOOL }) },
	{ .name = "compress_max_concurrent", .contexts = GSL, .apply = ap_max_concurrent,
	  .default_value = "1024",
	  .doc = "Compressed streams one worker runs at once; past it responses go uncompressed. The "
		 "compressors' memory is charged to worker_memory as well, and a stream whose "
		 "compressor does not fit goes uncompressed too.",
	  UP1({ .kind = BST_T_INT, .min = 1, .max = 1000000 }) },
};
BST_DIRECTIVES(compress_dirs);
