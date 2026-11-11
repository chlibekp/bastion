/* libFuzzer harness for the HTTP/2 frame parser. The input is a byte stream of frames, fed whole
 * and again one byte at a time.
 *
 * Properties: no crash or sanitizer report; the parser never reports more bytes used than it was
 * given; a returned frame's views lie inside the input; and a frame parses the same whole or
 * arriving piecemeal (the same frames, in the same order, with the same outcome). */
#include "http/h2/frame.h"

#include <stdlib.h>
#include <string.h>

typedef struct sum {
	size_t frames;
	uint64_t h; /* running hash of what each frame said */
	int err;    /* 0, or the error code + 1 */
	uint32_t err_stream;
} sum;

static void mix(sum *s, const bst_h2_frame *f)
{
	uint64_t v = (uint64_t)f->type << 56 ^ (uint64_t)f->flags << 48 ^ (uint64_t)f->stream_id << 16 ^
		     f->length ^ (uint64_t)f->data_len << 32 ^ f->value ^ (uint64_t)f->last_stream << 7 ^
		     f->dep ^ (uint64_t)f->weight << 3;
	for (int i = 0; i < 8; i++)
		v ^= (uint64_t)f->ping[i] << (i * 5);
	if (f->data_len > 0)
		v ^= f->data[0] ^ (uint64_t)f->data[f->data_len - 1] << 9;
	s->h = (s->h ^ v) * 1099511628211ull;
	s->frames++;
}

/* piece: bytes made available per step (0: all at once). */
static void run(const uint8_t *in, size_t n, size_t piece, uint32_t max_frame, sum *out)
{
	memset(out, 0, sizeof *out);
	out->h = 1469598103934665603ull;
	size_t have = 0, used = 0;
	while (out->err == 0) {
		size_t avail = piece ? (have + piece < n ? have + piece : n) : n;
		bst_h2_frame f;
		bst_h2_err e;
		ssize_t r = bst_h2_frame_parse(in + used, avail - used, max_frame, &f, &e);
		if (r < 0) {
			out->err = (int)e.code + 1;
			out->err_stream = e.stream;
			return;
		}
		if (r == 0) {
			if (avail == n)
				return;
			have = avail;
			continue;
		}
		if ((size_t)r > avail - used)
			abort();
		if (f.data_len > 0 && (f.data < in + used || f.data + f.data_len > in + used + r))
			abort();
		mix(out, &f);
		used += (size_t)r;
		have = used > have ? used : have;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size)
{
	if (size < 1)
		return 0;
	uint32_t max_frame = (d[0] & 1) ? 64 : BST_H2_MIN_FRAME;
	sum whole, bytes;
	run(d + 1, size - 1, 0, max_frame, &whole);
	run(d + 1, size - 1, 1, max_frame, &bytes);
	if (whole.frames != bytes.frames || whole.h != bytes.h || whole.err != bytes.err ||
	    whole.err_stream != bytes.err_stream)
		abort();
	return 0;
}
