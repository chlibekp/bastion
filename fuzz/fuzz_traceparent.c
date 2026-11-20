/* libFuzzer harness for the W3C traceparent parser (filters/trace.c). The input is copied to an
 * exact-size heap block. Properties: no crash; an accepted value has non-zero trace and parent
 * IDs and a version other than ff; formatting it and parsing the result gives the same IDs and
 * flags with version 00; and a version 00 input that is accepted round-trips byte for byte. */
#include "filters/trace.h"

#include <stdlib.h>
#include <string.h>

static bool zero(const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (p[i] != 0)
			return false;
	return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size > 512)
		return 0;
	char *buf = malloc(size > 0 ? size : 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, d, size);
	bst_traceparent tp, back;
	memset(&tp, 0xa5, sizeof tp);
	bst_traceparent before = tp;
	if (bst_traceparent_parse((bst_str){ buf, (uint32_t)size }, &tp)) {
		if (tp.version == 0xff || zero(tp.trace_id, 16) || zero(tp.parent_id, 8))
			abort();
		char out[BST_TRACEPARENT_LEN + 1];
		bst_traceparent_format(&tp, out);
		if (strlen(out) != BST_TRACEPARENT_LEN)
			abort();
		if (!bst_traceparent_parse((bst_str){ out, BST_TRACEPARENT_LEN }, &back))
			abort();
		if (back.version != 0 || memcmp(back.trace_id, tp.trace_id, 16) != 0 ||
		    memcmp(back.parent_id, tp.parent_id, 8) != 0 || back.flags != tp.flags)
			abort();
		if (tp.version == 0 && (size != BST_TRACEPARENT_LEN || memcmp(out, buf, size) != 0))
			abort();
	} else if (memcmp(&tp, &before, sizeof tp) != 0) {
		abort(); /* rejected values leave tp untouched */
	}
	free(buf);
	return 0;
}
