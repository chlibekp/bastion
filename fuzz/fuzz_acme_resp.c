/* libFuzzer harness for ACME server responses: the blocking client's HTTP/1.1 response parser
 * (ops/http_client.c) and then the JSON walk the ACME job does over a body (directory, order,
 * authorization, problem documents). The input is copied to an exact-size heap block so ASan
 * flags any read past len. First byte: bit 0 selects head-only parsing.
 * Properties: no crash; an accepted response has a status in 100..999, a body no larger than
 * the input and NUL-terminated, and NUL-terminated header copies. */
#include "core/arena.h"
#include "core/json.h"
#include "ops/http_client.h"

#include <stdlib.h>
#include <string.h>

static void str_field(const bst_json *o, const char *key)
{
	bst_str s;
	const bst_json *v = o != NULL ? bst_json_get(o, key) : NULL;
	if (v != NULL && bst_json_str(v, &s) && s.len > 0 && s.p == NULL)
		abort();
}

static void walk(const char *body, size_t len)
{
	bst_arena *a = bst_arena_new(4096);
	if (a == NULL)
		return;
	bst_err e;
	const bst_json *v = bst_json_parse(a, body, len, &e);
	if (v != NULL && bst_json_typeof(v) == BST_JSON_OBJ) {
		static const char *keys[] = { "newNonce", "newAccount", "newOrder", "renewalInfo", "status",
					      "finalize", "certificate", "detail", "type", "token", "url" };
		for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++)
			str_field(v, keys[i]);
		str_field(bst_json_get(v, "identifier"), "value");
		str_field(bst_json_get(v, "suggestedWindow"), "start");
		str_field(bst_json_get(v, "suggestedWindow"), "end");
		const bst_json *cs = bst_json_get(v, "challenges");
		for (size_t i = 0; cs != NULL && i < bst_json_arr_len(cs); i++) {
			const bst_json *ch = bst_json_arr_at(cs, i);
			str_field(ch, "type");
			str_field(ch, "token");
			str_field(bst_json_get(ch, "error"), "detail");
		}
		const bst_json *az = bst_json_get(v, "authorizations");
		for (size_t i = 0; az != NULL && i < bst_json_arr_len(az); i++) {
			bst_str s;
			(void)bst_json_str(bst_json_arr_at(az, i), &s);
		}
	}
	bst_arena_free(a);
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size < 1 || size > (1u << 16))
		return 0;
	bool head_only = d[0] & 1;
	size_t n = size - 1;
	char *buf = malloc(n > 0 ? n : 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, d + 1, n);
	bst_hc_resp r;
	memset(&r, 0, sizeof r);
	char err[256];
	if (bst_hc_parse_response(buf, n, head_only, &r, err, sizeof err) == 0) {
		if (r.status < 100 || r.status > 999)
			abort();
		if (r.len > n || (r.body != NULL && r.body[r.len] != '\0'))
			abort();
		if (memchr(r.location, '\0', sizeof r.location) == NULL ||
		    memchr(r.nonce, '\0', sizeof r.nonce) == NULL ||
		    memchr(r.retry_after, '\0', sizeof r.retry_after) == NULL ||
		    memchr(r.content_type, '\0', sizeof r.content_type) == NULL ||
		    memchr(r.link_up, '\0', sizeof r.link_up) == NULL)
			abort();
		if (r.body != NULL && r.len > 0)
			walk(r.body, r.len);
	} else if (memchr(err, '\0', sizeof err) == NULL) {
		abort();
	}
	bst_hc_resp_free(&r);
	free(buf);
	return 0;
}
