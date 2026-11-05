/* libFuzzer harness for the strict JSON parser. The input is copied to an exact-size heap
 * block so ASan flags any read past len. Properties: any accepted document writes back
 * through bst_jw_value to text that parses again to an equal value (same types, number
 * text, strings, and key order), bst_json_int never crashes on any number, and arbitrary
 * bytes through bst_jw_str_lossy always form a document the parser accepts. */
#include "core/arena.h"
#include "core/json.h"

#include <stdlib.h>
#include <string.h>

static bool equal(const bst_json *a, const bst_json *b)
{
	if (bst_json_typeof(a) != bst_json_typeof(b))
		return false;
	bst_str x, y;
	bool p, q;
	switch (bst_json_typeof(a)) {
	case BST_JSON_NULL:
		return true;
	case BST_JSON_BOOL:
		return bst_json_bool(a, &p) && bst_json_bool(b, &q) && p == q;
	case BST_JSON_NUM:
		return bst_json_num_text(a, &x) && bst_json_num_text(b, &y) && bst_str_eq(x, y);
	case BST_JSON_STR:
		return bst_json_str(a, &x) && bst_json_str(b, &y) && bst_str_eq(x, y);
	case BST_JSON_ARR:
		if (bst_json_arr_len(a) != bst_json_arr_len(b))
			return false;
		for (size_t i = 0; i < bst_json_arr_len(a); i++)
			if (!equal(bst_json_arr_at(a, i), bst_json_arr_at(b, i)))
				return false;
		return true;
	case BST_JSON_OBJ:
		if (bst_json_arr_len(a) != bst_json_arr_len(b))
			return false;
		for (size_t i = 0; i < bst_json_arr_len(a); i++) {
			const bst_json *va = bst_json_obj_at(a, i, &x);
			const bst_json *vb = bst_json_obj_at(b, i, &y);
			if (!bst_str_eq(x, y) || !equal(va, vb))
				return false;
		}
		return true;
	}
	return false;
}

static void walk_ints(const bst_json *j)
{
	int64_t v;
	switch (bst_json_typeof(j)) {
	case BST_JSON_NUM:
		(void)bst_json_int(j, &v);
		break;
	case BST_JSON_ARR:
	case BST_JSON_OBJ:
		for (size_t i = 0; i < bst_json_arr_len(j); i++)
			walk_ints(bst_json_obj_at(j, i, NULL) ? bst_json_obj_at(j, i, NULL)
							       : bst_json_arr_at(j, i));
		break;
	default:
		break;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size > (1u << 20))
		return 0;
	char *copy = malloc(size ? size : 1);
	bst_arena *a = bst_arena_new(1 << 16);
	if (!copy || !a)
		abort();
	memcpy(copy, d, size);
	bst_err e;
	bst_json *j = bst_json_parse(a, copy, size, &e);
	if (j) {
		walk_ints(j);
		bst_jw w;
		bst_jw_init(&w);
		bst_jw_value(&w, j);
		if (!bst_jw_finish(&w))
			abort();
		bst_json *k = bst_json_parse(a, w.buf, w.len, &e);
		if (!k || !equal(j, k))
			abort();
		bst_jw_free(&w);
	}
	bst_jw lw;
	bst_jw_init(&lw);
	bst_jw_str_lossy(&lw, (bst_str){ copy, (uint32_t)size });
	if (!bst_jw_finish(&lw) || !bst_json_parse(a, lw.buf, lw.len, &e))
		abort();
	bst_jw_free(&lw);
	bst_arena_free(a);
	free(copy);
	return 0;
}
