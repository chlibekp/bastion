/* The ticket key ring (tls/tickets.c): rotation, keep, the key file, and the seqlock. */
#include "core/alloc.h"
#include "tap.h"
#include "tls/tickets.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stddef.h>
#include <unistd.h>

static void *region(void)
{
	void *r = aligned_alloc(64, 4096);
	memset(r, 0, 4096);
	return r;
}

TEST(init_and_rotate_keep)
{
	void *r = region();
	bst_err e = { .msg = "" };
	ASSERT_EQ(bst_tickets_init(r, 3, NULL, &e), 0);
	bst_ticket_key k[BST_TICKET_KEYS_MAX];
	ASSERT_EQ(bst_tickets_snapshot(r, k, BST_TICKET_KEYS_MAX), 1);
	unsigned char first[16];
	memcpy(first, k[0].name, 16);
	for (int i = 0; i < 5; i++)
		ASSERT_EQ(bst_tickets_rotate(r, 3), 0);
	unsigned n = bst_tickets_snapshot(r, k, BST_TICKET_KEYS_MAX);
	ASSERT_EQ(n, 3); /* never more than keep */
	for (unsigned i = 0; i < n; i++) {
		ASSERT(memcmp(k[i].name, first, 16) != 0); /* the first key aged out */
		for (unsigned j = i + 1; j < n; j++)
			ASSERT(memcmp(k[i].name, k[j].name, 16) != 0);
	}
	/* keep 1: only the newest remains */
	ASSERT_EQ(bst_tickets_rotate(r, 1), 0);
	ASSERT_EQ(bst_tickets_snapshot(r, k, BST_TICKET_KEYS_MAX), 1);
	free(r);
}

TEST(snapshot_of_nothing)
{
	ASSERT_EQ(bst_tickets_snapshot(NULL, NULL, 0), 0);
	void *r = region();
	bst_ticket_key k[2];
	ASSERT_EQ(bst_tickets_snapshot(r, k, 2), 0);
	free(r);
}

static const char *HEXKEY(char c)
{
	static char buf[8][161];
	static int n;
	char *b = buf[n++ & 7];
	memset(b, c, 160);
	b[160] = '\0';
	return b;
}

TEST(key_file)
{
	const char *path = "build/tickets-test.keys";
	FILE *f = fopen(path, "w");
	ASSERT(f != NULL);
	fprintf(f, "# newest first\n%s\n\n%s\n", HEXKEY('a'), HEXKEY('b'));
	fclose(f);
	chmod(path, 0600);
	void *r = region();
	bst_err e = { .msg = "" };
	ASSERT_EQ(bst_tickets_init(r, 3, path, &e), 0);
	bst_ticket_key k[4];
	ASSERT_EQ(bst_tickets_snapshot(r, k, 4), 2);
	ASSERT_EQ(k[0].name[0], 0xaa);
	ASSERT_EQ(k[1].aes[5], 0xbb);
	ASSERT_EQ(bst_tickets_init(r, 1, path, &e), 0); /* keep caps what is loaded */
	ASSERT_EQ(bst_tickets_snapshot(r, k, 4), 1);
	/* group-readable: refused */
	chmod(path, 0640);
	ASSERT_EQ(bst_tickets_init(r, 3, path, &e), -1);
	ASSERT(strstr(e.msg, "chmod 600") != NULL);
	chmod(path, 0600);
	/* short key, not hex, empty, missing */
	f = fopen(path, "w");
	fputs("abcd\n", f);
	fclose(f);
	ASSERT_EQ(bst_tickets_init(r, 3, path, &e), -1);
	f = fopen(path, "w");
	fprintf(f, "%s\n", HEXKEY('z'));
	fclose(f);
	ASSERT_EQ(bst_tickets_init(r, 3, path, &e), -1);
	f = fopen(path, "w");
	fputs("# nothing\n", f);
	fclose(f);
	ASSERT_EQ(bst_tickets_init(r, 3, path, &e), -1);
	ASSERT_EQ(bst_tickets_init(r, 3, "build/no-such-keys", &e), -1);
	unlink(path);
	free(r);
}

/* A writer publishes as fast as it can; readers must never see a key whose bytes differ, nor a
 * snapshot mixing two publications (generations of neighbours differ by exactly one). */
static atomic_bool stop;
static atomic_int torn;

static int uniform(const bst_ticket_key *k)
{
	for (int i = 1; i < 16; i++)
		if (k->name[i] != k->name[0])
			return 0;
	for (int i = 0; i < 32; i++)
		if (k->aes[i] != k->name[0] || k->hmac[i] != k->name[0])
			return 0;
	return 1;
}

static void *reader(void *arg)
{
	bst_ticket_key k[BST_TICKET_KEYS_MAX];
	while (!atomic_load(&stop)) {
		unsigned n = bst_tickets_snapshot(arg, k, BST_TICKET_KEYS_MAX);
		for (unsigned i = 0; i < n; i++)
			if (!uniform(&k[i]))
				atomic_fetch_add(&torn, 1);
		for (unsigned i = 1; i < n; i++) /* newest first: generations descend by one */
			if ((unsigned char)(k[i - 1].name[0] - k[i].name[0]) != 1)
				atomic_fetch_add(&torn, 1);
	}
	return NULL;
}

TEST(seqlock_consistency)
{
	void *r = region();
	bst_ticket_key init[4];
	memset(init, 0, sizeof init);
	bst_tickets_publish(r, init, 1);
	pthread_t t[3];
	for (int i = 0; i < 3; i++)
		pthread_create(&t[i], NULL, reader, r);
	/* Generation g publishes four keys made of the bytes g, g-1, g-2, g-3 (newest first). */
	for (int g = 3; g < 40000; g++) {
		bst_ticket_key k[4];
		for (int i = 0; i < 4; i++) {
			memset(&k[i], (unsigned char)(g - i), offsetof(bst_ticket_key, created_ms));
			k[i].created_ms = (uint64_t)g;
		}
		bst_tickets_publish(r, k, 4);
	}
	atomic_store(&stop, true);
	for (int i = 0; i < 3; i++)
		pthread_join(t[i], NULL);
	ASSERT_EQ(atomic_load(&torn), 0);
	free(r);
}

TAP_MAIN()
