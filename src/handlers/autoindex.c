/* `autoindex`: a directory as html or json, streamed. Every getdents batch (and the statx of its
 * entries) is one job on the aio pool, formatted there into one buffer the loop sends, so a
 * directory of a million entries holds one batch in memory and never blocks the loop. Names are
 * untrusted bytes: html and json escapes, invalid UTF-8 and control bytes become U+FFFD. */
#include "handlers/static_priv.h"

#include "core/log.h"
#include "io/aio.h"
#include "proc/worker.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define DIRBUF 8192

struct linux_dirent64 {
	unsigned long long d_ino;
	long long d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

typedef struct sb {
	char *p;
	size_t n, cap;
	bool bad;
} sb;

static void sb_put(sb *b, const char *s, size_t n)
{
	if (b->bad)
		return;
	if (b->n + n + 1 > b->cap) {
		size_t nc = b->cap ? b->cap * 2 : 4096;
		while (nc < b->n + n + 1)
			nc *= 2;
		char *np = realloc(b->p, nc);
		if (np == NULL) {
			b->bad = true;
			return;
		}
		b->p = np;
		b->cap = nc;
	}
	memcpy(b->p + b->n, s, n);
	b->n += n;
}

static void sb_str(sb *b, const char *s)
{
	sb_put(b, s, strlen(s));
}

/* Length of the valid UTF-8 character at p (at most n bytes left), 0 when it is not one or is a
 * control character. */
static size_t utf8_ok(const unsigned char *p, size_t n)
{
	if (p[0] < 0x20 || p[0] == 0x7f)
		return 0;
	if (p[0] < 0x80)
		return 1;
	if (p[0] >= 0xc2 && p[0] <= 0xdf)
		return n >= 2 && (p[1] & 0xc0) == 0x80 ? 2 : 0;
	if (p[0] >= 0xe0 && p[0] <= 0xef) {
		if (n < 3 || (p[1] & 0xc0) != 0x80 || (p[2] & 0xc0) != 0x80)
			return 0;
		if (p[0] == 0xe0 && p[1] < 0xa0)
			return 0; /* overlong */
		if (p[0] == 0xed && p[1] >= 0xa0)
			return 0; /* a surrogate */
		return 3;
	}
	if (p[0] >= 0xf0 && p[0] <= 0xf4) {
		if (n < 4 || (p[1] & 0xc0) != 0x80 || (p[2] & 0xc0) != 0x80 || (p[3] & 0xc0) != 0x80)
			return 0;
		if (p[0] == 0xf0 && p[1] < 0x90)
			return 0;
		if (p[0] == 0xf4 && p[1] >= 0x90)
			return 0;
		return 4;
	}
	return 0;
}

static void esc_html(sb *b, const char *s, size_t n)
{
	for (size_t i = 0; i < n;) {
		unsigned char c = (unsigned char)s[i];
		size_t l = utf8_ok((const unsigned char *)s + i, n - i);
		if (l == 0) {
			sb_str(b, "&#xFFFD;");
			i++;
		} else if (l == 1 && (c == '&' || c == '<' || c == '>' || c == '"' || c == '\'')) {
			sb_str(b, c == '&' ? "&amp;" : c == '<' ? "&lt;" : c == '>' ? "&gt;" : c == '"' ? "&quot;" : "&#39;");
			i++;
		} else {
			sb_put(b, s + i, l);
			i += l;
		}
	}
}

static void esc_json(sb *b, const char *s, size_t n)
{
	for (size_t i = 0; i < n;) {
		unsigned char c = (unsigned char)s[i];
		size_t l = utf8_ok((const unsigned char *)s + i, n - i);
		if (l == 0) {
			sb_str(b, "\\ufffd");
			i++;
		} else if (l == 1 && (c == '"' || c == '\\')) {
			sb_put(b, "\\", 1);
			sb_put(b, s + i, 1);
			i++;
		} else {
			sb_put(b, s + i, l);
			i += l;
		}
	}
}

static void esc_url(sb *b, const char *s, size_t n)
{
	static const char hex[] = "0123456789ABCDEF";
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		    c == '-' || c == '.' || c == '_' || c == '~') {
			sb_put(b, s + i, 1);
		} else {
			char t[3] = { '%', hex[c >> 4], hex[c & 15] };
			sb_put(b, t, 3);
		}
	}
}

enum { IX_IDLE, IX_READING, IX_SENDING };

struct bst_static_ix {
	bst_stream *s;
	bst_loop *loop;
	bst_file *dir;
	bool json, dotfiles;
	bst_symlinks sl;
	char *title; /* the request path, copied: the stream's arena may go */
	size_t title_len;
	bool first; /* no entry written yet (json comma) */
	bool started; /* the header is written */
	bool eof;   /* the last batch was empty */
	int err;
	int state;
	bool alive;
	sb out;
	char dirbuf[DIRBUF];
	struct bst_static_ix **slot;
};
typedef struct bst_static_ix ix;

static void cleanup(ix *x)
{
	bst_file_unref(x->dir);
	if (x->slot != NULL && *x->slot == x)
		*x->slot = NULL;
	free(x->out.p);
	free(x->title);
	free(x);
}

static void header(ix *x)
{
	if (x->json) {
		sb_str(&x->out, "[");
		return;
	}
	sb_str(&x->out, "<html><head><meta charset=\"utf-8\"><title>Index of ");
	esc_html(&x->out, x->title, x->title_len);
	sb_str(&x->out, "</title></head><body><h1>Index of ");
	esc_html(&x->out, x->title, x->title_len);
	sb_str(&x->out, "</h1><hr><pre>");
	if (x->title_len > 1)
		sb_str(&x->out, "<a href=\"../\">../</a>\n");
}

static void entry(ix *x, const char *name, size_t nlen, bool dir, long long size, time_t mt,
		  bool has_stat)
{
	char date[BST_HTTP_DATE_LEN + 1] = "";
	if (has_stat && bst_http_date_format(mt, date) != BST_HTTP_DATE_LEN)
		date[0] = '\0';
	char num[32];
	if (has_stat && !dir)
		snprintf(num, sizeof num, "%lld", size);
	else
		snprintf(num, sizeof num, "-");
	sb *b = &x->out;
	if (x->json) {
		sb_str(b, x->first ? "\n" : ",\n");
		sb_str(b, "{\"name\":\"");
		esc_json(b, name, nlen);
		sb_str(b, "\",\"type\":\"");
		sb_str(b, dir ? "directory" : "file");
		sb_str(b, "\",\"mtime\":\"");
		sb_str(b, date);
		sb_str(b, "\",\"size\":");
		sb_str(b, has_stat && !dir ? num : "null");
		sb_str(b, "}");
	} else {
		sb_str(b, "<a href=\"");
		esc_url(b, name, nlen);
		if (dir)
			sb_str(b, "/");
		sb_str(b, "\">");
		esc_html(b, name, nlen);
		if (dir)
			sb_str(b, "/");
		sb_str(b, "</a> ");
		sb_str(b, date);
		sb_str(b, " ");
		sb_str(b, num);
		sb_str(b, "\n");
	}
	x->first = false;
}

static void work(void *arg)
{
	ix *x = arg;
	x->out.n = 0;
	if (!x->started) {
		header(x);
		x->started = true;
	}
	long n;
	do
		n = syscall(SYS_getdents64, x->dir->fd, x->dirbuf, sizeof x->dirbuf);
	while (n < 0 && errno == EINTR);
	if (n < 0) {
		x->err = errno;
		return;
	}
	if (n == 0) {
		x->eof = true;
		sb_str(&x->out, x->json ? "\n]\n" : "</pre><hr></body></html>\n");
		return;
	}
	for (long off = 0; off < n;) {
		struct linux_dirent64 *d = (struct linux_dirent64 *)(x->dirbuf + off);
		off += d->d_reclen;
		const char *nm = d->d_name;
		size_t nl = strlen(nm);
		if ((nl == 1 && nm[0] == '.') || (nl == 2 && nm[0] == '.' && nm[1] == '.'))
			continue;
		if (!x->dotfiles && nm[0] == '.')
			continue;
		bool isdir = d->d_type == DT_DIR, link = d->d_type == DT_LNK;
		if (link) {
			if (x->sl == BST_SYMLINKS_OFF)
				continue; /* it would be a 404: not listed */
			entry(x, nm, nl, false, 0, 0, false);
			continue;
		}
		if (d->d_type != DT_DIR && d->d_type != DT_REG && d->d_type != DT_UNKNOWN)
			continue; /* FIFOs, sockets, devices are never served */
		struct statx sx;
		if (statx(x->dir->fd, nm, AT_SYMLINK_NOFOLLOW | AT_STATX_DONT_SYNC,
			  STATX_TYPE | STATX_SIZE | STATX_MTIME, &sx) != 0)
			continue; /* gone since getdents */
		if (S_ISDIR(sx.stx_mode))
			isdir = true;
		else if (!S_ISREG(sx.stx_mode))
			continue;
		entry(x, nm, nl, isdir, (long long)sx.stx_size, (time_t)sx.stx_mtime.tv_sec, true);
	}
}

static void submit(ix *x);

static void sent(void *ud, size_t n, int err)
{
	(void)n;
	ix *x = ud;
	if (err != 0)
		return;
	x->state = IX_IDLE;
	submit(x);
}

static void fail(ix *x)
{
	bst_stream *s = x->s;
	x->alive = false;
	cleanup(x);
	s->ops->reset(s, BST_STREAM_ERR_INTERNAL);
}

static void done(void *arg)
{
	ix *x = arg;
	x->state = IX_IDLE;
	if (!x->alive) {
		cleanup(x);
		return;
	}
	if (x->err != 0 || x->out.bad) {
		bst_log(BST_LOG_WARN, "autoindex: listing failed (%s): aborting the response",
			x->err != 0 ? strerror(x->err) : "out of memory");
		fail(x);
		return;
	}
	if (x->out.n == 0) { /* a batch of names that are all hidden: read the next */
		submit(x);
		return;
	}
	bst_buf *b = bst_buf_new(x->out.n);
	bst_chain *c = b != NULL ? bst_arena_alloc(x->s->arena, sizeof *c) : NULL;
	if (c == NULL) {
		bst_buf_unref(b);
		fail(x);
		return;
	}
	memcpy(b->data, x->out.p, x->out.n);
	b->len = x->out.n;
	bst_chain_init(c, x->s->chain_slab);
	int rc = bst_chain_add_mem(c, b, 0, b->len);
	bst_buf_unref(b);
	if (rc != 0) {
		fail(x);
		return;
	}
	x->state = IX_SENDING;
	bool end = x->eof;
	if (bst_stream_send_body(x->s, c, end, end ? NULL : sent, x) != 0) {
		x->alive = false;
		cleanup(x);
		return;
	}
	if (end) { /* complete: no on_reset follows, and the stream's memory may be gone */
		x->slot = NULL;
		x->alive = false;
		cleanup(x);
	}
}

static void submit(ix *x)
{
	x->state = IX_READING;
	if (bst_aio_submit(x->loop, work, done, x) != 0) {
		x->state = IX_IDLE;
		bst_log(BST_LOG_WARN, "autoindex: the read queue is full: aborting the response");
		fail(x);
	}
}

int bst_autoindex_start(bst_stream *s, bst_file *dir, bst_str uri, bool json, bool dotfiles,
			bst_symlinks sl, struct bst_static_ix **slot)
{
	ix *x = calloc(1, sizeof *x);
	if (x == NULL)
		return -1;
	x->title = malloc((size_t)uri.len + 1);
	if (x->title == NULL) {
		free(x);
		return -1;
	}
	memcpy(x->title, uri.p, uri.len);
	x->title_len = uri.len;
	x->s = s;
	x->loop = bst_worker_loop(s->worker);
	x->dir = bst_file_ref(dir);
	x->json = json;
	x->dotfiles = dotfiles;
	x->sl = sl;
	x->first = true;
	x->alive = true;
	x->slot = slot;
	bst_resp_head h;
	memset(&h, 0, sizeof h);
	h.status = 200;
	h.content_length = -1;
	bst_headers_init(&h.headers, s->arena);
	if (bst_headers_add(&h.headers, BST_S("Content-Type"),
			    json ? BST_S("application/json; charset=utf-8")
				 : BST_S("text/html; charset=utf-8")) != 0 ||
	    bst_stream_send_head(s, &h, false) != 0) {
		bst_file_unref(x->dir);
		free(x->title);
		free(x);
		return -1;
	}
	*slot = x;
	submit(x);
	return 0;
}

void bst_autoindex_abort(struct bst_static_ix *x)
{
	if (x == NULL)
		return;
	if (x->slot != NULL) {
		*x->slot = NULL;
		x->slot = NULL;
	}
	x->alive = false;
	if (x->state != IX_READING)
		cleanup(x);
}
