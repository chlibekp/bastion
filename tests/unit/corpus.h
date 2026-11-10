/* Reads the request corpora of tests/corpus (see its README): `<expect>-<name>.req` files with LF
 * line ends, every LF read as CRLF, and \r \n \0 \xHH \\ as escapes. Header-only, for the unit
 * tests that run from the repository root. */
#ifndef BST_TEST_CORPUS_H
#define BST_TEST_CORPUS_H

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct corpus_entry {
	char name[96];
	int expect; /* 0 for ok, else the status */
	char *data;
	size_t len;
} corpus_entry;

static inline int corpus_hex(int c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10
				       : c >= 'A' && c <= 'F'	     ? c - 'A' + 10
								     : -1;
}

/* Decodes text of n bytes into a fresh buffer; NULL on a bad escape. */
static inline char *corpus_decode(const char *t, size_t n, size_t *outlen)
{
	char *out = malloc(n * 2 + 1);
	size_t o = 0;
	for (size_t i = 0; out && i < n; i++) {
		if (t[i] == '\n') {
			out[o++] = '\r';
			out[o++] = '\n';
		} else if (t[i] != '\\') {
			out[o++] = t[i];
		} else if (i + 1 < n && t[i + 1] == 'r') {
			out[o++] = '\r', i++;
		} else if (i + 1 < n && t[i + 1] == 'n') {
			out[o++] = '\n', i++;
		} else if (i + 1 < n && t[i + 1] == '0') {
			out[o++] = '\0', i++;
		} else if (i + 1 < n && t[i + 1] == '\\') {
			out[o++] = '\\', i++;
		} else if (i + 3 < n && t[i + 1] == 'x' && corpus_hex(t[i + 2]) >= 0 &&
			   corpus_hex(t[i + 3]) >= 0) {
			out[o++] = (char)(corpus_hex(t[i + 2]) * 16 + corpus_hex(t[i + 3]));
			i += 3;
		} else {
			free(out);
			return NULL;
		}
	}
	*outlen = o;
	return out;
}

static int corpus_cmp(const void *a, const void *b)
{
	return strcmp(((const corpus_entry *)a)->name, ((const corpus_entry *)b)->name);
}

/* Every .req file of dir, sorted by name. Returns the count, 0 when the directory is missing
 * or empty (a test then fails: a corpus that vanished is a defect). */
static inline size_t corpus_load(const char *dir, corpus_entry **out)
{
	DIR *d = opendir(dir);
	*out = NULL;
	if (d == NULL)
		return 0;
	size_t n = 0, cap = 0;
	for (struct dirent *e; (e = readdir(d)) != NULL;) {
		size_t nl = strlen(e->d_name);
		if (nl < 5 || strcmp(e->d_name + nl - 4, ".req") != 0 || nl >= 90)
			continue;
		char path[512];
		snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
		FILE *f = fopen(path, "rb");
		if (f == NULL)
			continue;
		char *raw = malloc(1 << 16);
		size_t rl = raw ? fread(raw, 1, 1 << 16, f) : 0;
		fclose(f);
		if (n == cap) {
			cap = cap ? cap * 2 : 64;
			*out = realloc(*out, cap * sizeof **out);
		}
		corpus_entry *c = &(*out)[n];
		snprintf(c->name, sizeof c->name, "%.*s", (int)(nl - 4), e->d_name);
		c->expect = strncmp(c->name, "ok-", 3) == 0 ? 0 : atoi(c->name);
		c->data = corpus_decode(raw, rl, &c->len);
		free(raw);
		if (c->data == NULL) {
			fprintf(stderr, "corpus: bad escape in %s\n", path);
			abort();
		}
		n++;
	}
	closedir(d);
	qsort(*out, n, sizeof **out, corpus_cmp);
	return n;
}

#endif
