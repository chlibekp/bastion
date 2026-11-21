/* The disk object store of the cache: one file per object at <root>/ab/cd/<hex key>, where the
 * key is the SHA-256 of the cache key and ab, cd are its first two bytes.
 *
 * File layout: a fixed header (magic, format version, a copy of the key, the times, status,
 * blob lengths, the body's offset and length, and a SHA-256 over the header and blobs), then
 * the blobs (response fields, Vary data, tag hashes), then padding to a page boundary, then the
 * body. The body starts page-aligned so a hit can be sent as a file segment (sendfile, splice).
 *
 * Crash safety. An object is written to <root>/tmp/<hex>.<pid>.<n> and renamed into place by
 * commit, after the header that names the body length is written: a reader sees a complete
 * object or none. A process killed mid-fill leaves a temp file, never a partial object; the
 * helper's startup scan removes temp files. A file that fails any check (magic, version, header
 * hash, key, length) is treated as a miss, counted and deleted.
 *
 * Threads. Reads run on the aio pool (bst_store_open_read). Workers write through
 * bst_store_async_*, which runs every disk call on the aio pool too; the synchronous writer is
 * for tests and tools off an event loop. Directories are made on first use (mkdirat). No fsync: a power loss may lose recent objects, never serve a
 * torn one (the header hash and the length check catch it). */
#ifndef BST_CACHE_STORE_H
#define BST_CACHE_STORE_H

#include "core/str.h"
#include "io/loop.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BST_STORE_MAGIC "BSTCACH"
#define BST_STORE_VERSION 1u
#define BST_STORE_MAX_TAGS 64
#define BST_STORE_PAGE 4096u

typedef struct bst_key {
	uint8_t b[32];
} bst_key;

/* SHA-256 of s. */
void bst_key_make(bst_str s, bst_key *k);
/* 64 lower-case hex digits and a NUL. */
void bst_key_hex(const bst_key *k, char out[65]);
/* The first 8 bytes as a number: the index and purge tables hash by it. */
uint64_t bst_key_u64(const bst_key *k);

/* What an object carries besides its body. head: the response fields as "name\0value\0" pairs. */
typedef struct bst_sobj_meta {
	int64_t stored_at_ms; /* when the request that filled it began (purge compares this) */
	int64_t req_time, resp_time; /* seconds: for the age calculation */
	int status;
	uint64_t body_len;
	bst_str head;
	bst_str vary;
	const uint64_t *tags; /* tag hashes */
	uint32_t ntags;
	uint64_t host_hash;
} bst_sobj_meta;

typedef struct bst_store {
	int dirfd;	  /* the root, O_PATH, not owned */
	atomic_ullong corrupt; /* objects found broken and deleted */
	atomic_ullong write_errors;
	uint64_t seq;	  /* temp file names */
#ifdef BST_TEST
	int64_t test_space; /* > 0: bytes a writer may write before -ENOSPC */
#endif
} bst_store;

void bst_store_init(bst_store *st, int dirfd);

/* An opened object: fd at body_off holds body_len bytes. The blobs are in memory owned here. */
typedef struct bst_sobj {
	int fd;
	bst_key key;
	bst_sobj_meta m;
	uint64_t body_off;
	char *blob;
	uint64_t tagbuf[BST_STORE_MAX_TAGS];
} bst_sobj;

/* Opens and checks the object for key, synchronously. 0 with *out set; -ENOENT when there is
 * none; -EBADMSG when it was broken (it is deleted and counted); another negative errno. */
int bst_store_read_sync(bst_store *st, const bst_key *k, bst_sobj **out);
/* The same on the aio pool; cb runs on the loop thread. 0 when submitted, else a negative errno
 * (cb does not run then). */
typedef void (*bst_store_read_cb)(void *ud, bst_sobj *o, int err);
int bst_store_open_read(bst_store *st, bst_loop *l, const bst_key *k, bst_store_read_cb cb, void *ud);
/* Closes the fd (unless fd was taken: set it to -1) and frees. NULL is fine. */
void bst_sobj_free(bst_sobj *o);
/* The stored fields as a header list in arena a (views into o->blob). -1 on exhaustion. */
struct bst_headers;
struct bst_arena;
int bst_sobj_headers(const bst_sobj *o, struct bst_headers *out, struct bst_arena *a);

typedef struct bst_swriter bst_swriter;
/* Starts an object: the temp file is made and the body goes at a page boundary after the
 * header. m->body_len is ignored (commit writes what was written). NULL with errno set. */
bst_swriter *bst_store_begin_write(bst_store *st, const bst_key *k, const bst_sobj_meta *m);
/* Appends body bytes. 0, or a negative errno (-ENOSPC); after an error only abort is useful. */
int bst_store_write(bst_swriter *w, const void *p, size_t n);
uint64_t bst_swriter_size(const bst_swriter *w);
/* Writes the header and renames the object into place. Frees w. 0 or a negative errno (the
 * temp file is removed then). */
int bst_store_commit(bst_swriter *w);
/* Removes the temp file and frees w. NULL is fine. */
void bst_store_abort(bst_swriter *w);
/* The same writer for a worker's event loop (NFR5): every disk call (open, mkdir, pwrite,
 * ftruncate, rename, unlink) runs on the aio pool, one job at a time per object, in order.
 * begin copies m and touches no disk; NULL with errno set (EINVAL, E2BIG, ENOMEM). write copies
 * the bytes into a queue: 0; -ENOBUFS when more than queue_max bytes would wait for the disk (a
 * slow disk: the caller abandons the fill rather than buffer without bound); or the first
 * failure of an earlier job (-ENOSPC), after which only commit or abort is useful. commit
 * writes what is queued, then the header, and renames the object into place; cb runs once on
 * the loop thread with 0 or a negative errno (the temp file is removed then), and the writer is
 * freed. abort drops what is queued and removes the temp file; cb never runs. Loop thread only. */
typedef struct bst_sawriter bst_sawriter;
typedef void (*bst_store_commit_cb)(void *ud, int err);
bst_sawriter *bst_store_async_begin(bst_store *st, bst_loop *l, const bst_key *k,
				    const bst_sobj_meta *m, uint64_t queue_max);
int bst_store_async_write(bst_sawriter *w, const void *p, size_t n);
uint64_t bst_sawriter_size(const bst_sawriter *w); /* bytes accepted */
uint64_t bst_sawriter_queued(const bst_sawriter *w); /* bytes accepted, not yet written */
void bst_store_async_commit(bst_sawriter *w, bst_store_commit_cb cb, void *ud);
void bst_store_async_abort(bst_sawriter *w); /* NULL is fine */
/* bst_store_delete on the aio pool; the outcome is not reported. 0, or -ENOMEM. */
int bst_store_async_delete(bst_store *st, bst_loop *l, const bst_key *k);

/* Removes the object for key. 0, or a negative errno (-ENOENT when none). */
int bst_store_delete(bst_store *st, const bst_key *k);
/* "ab/cd/<hex>" for key, NUL-terminated. */
void bst_store_path(const bst_key *k, char out[71]);
/* Reads only the header of the file at rel (for the startup scan): key, size on disk, and
 * meta (blob views are not kept). 0, or a negative errno; a broken file is not deleted here. */
int bst_store_peek(bst_store *st, const char *rel, bst_key *k, bst_sobj_meta *m, uint64_t *disk);

#endif
