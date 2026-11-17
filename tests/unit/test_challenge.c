/* The challenge's tokens, proofs and passes (sec/challenge.h): a full flow, tampering, expiry,
 * other networks, difficulty boundaries and secret rotation. */
#include "sec/attack.h"
#include "sec/challenge.h"
#include "tap.h"

#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

static const uint8_t KEY[BST_CHALLENGE_KEY_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
						    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

static bst_challenge_cfg cfg(unsigned bits)
{
	bst_challenge_cfg c;
	memset(&c, 0, sizeof c);
	c.mode = BST_CHAL_ON;
	c.difficulty = bits;
	c.pass_ttl_s = 3600;
	c.token_ttl_s = 300;
	c.prefix4 = 24;
	c.prefix6 = 56;
	return c;
}

static bst_ip ip(const char *s)
{
	bst_ip a;
	if (!bst_addr_parse((bst_str){ s, (uint32_t)strlen(s) }, &a))
		abort();
	return a;
}

static bst_str S_(const char *s)
{
	return (bst_str){ s, (uint32_t)strlen(s) };
}

static unsigned zero_bits(const char *token, const char *nonce)
{
	char buf[256];
	snprintf(buf, sizeof buf, "%s.%s", token, nonce);
	uint8_t h[32];
	SHA256((const unsigned char *)buf, strlen(buf), h);
	unsigned n = 0;
	for (int i = 0; i < 32; i++) {
		if (h[i] == 0) {
			n += 8;
			continue;
		}
		for (int b = 7; b >= 0 && !(h[i] >> b & 1); b--)
			n++;
		break;
	}
	return n;
}

/* The first nonce with at least `bits` zero bits; and through *exact the first with exactly bits. */
static unsigned long solve(const char *token, unsigned bits, unsigned long *exact)
{
	char nb[24];
	unsigned long first = 0;
	bool have = false;
	*exact = (unsigned long)-1;
	for (unsigned long n = 0; n < 50000000ul; n++) {
		snprintf(nb, sizeof nb, "%lu", n);
		unsigned z = zero_bits(token, nb);
		if (z >= bits && !have) {
			first = n;
			have = true;
		}
		if (z == bits && *exact == (unsigned long)-1)
			*exact = n;
		if (have && *exact != (unsigned long)-1)
			break;
	}
	return first;
}

TEST(valid_flow)
{
	bst_challenge_use_key(KEY);
	bst_challenge_cfg c = cfg(8);
	bst_ip a = ip("198.51.100.20");
	uint64_t now = 1700000000;
	char tok[BST_CHALLENGE_TOKEN_MAX], nb[24], pass[BST_CHALLENGE_PASS_MAX];
	ASSERT(bst_challenge_issue(&c, &a, now, tok, sizeof tok) > 0);
	unsigned long exact;
	snprintf(nb, sizeof nb, "%lu", solve(tok, 8, &exact));
	ASSERT(bst_challenge_verify_pow(&c, S_(tok), S_(nb), &a, now + 10));
	ASSERT(bst_challenge_pass(&c, &a, now + 10, pass, sizeof pass) > 0);
	ASSERT(bst_challenge_cookie_valid(&c, S_(pass), &a, now + 20));
	/* the same /24 is the same client; IPv4-mapped too */
	bst_ip b = ip("198.51.100.250"), m = ip("::ffff:198.51.100.20");
	ASSERT(bst_challenge_cookie_valid(&c, S_(pass), &b, now + 20));
	ASSERT(bst_challenge_cookie_valid(&c, S_(pass), &m, now + 20));
}

TEST(wrong_nonce_tampered_expired_token)
{
	bst_challenge_use_key(KEY);
	bst_challenge_cfg c = cfg(12);
	bst_ip a = ip("203.0.113.7");
	uint64_t now = 1700000000;
	char tok[BST_CHALLENGE_TOKEN_MAX], nb[24];
	ASSERT(bst_challenge_issue(&c, &a, now, tok, sizeof tok) > 0);
	unsigned long exact, good = solve(tok, 12, &exact);
	/* wrong nonces: one short of the work, and junk */
	for (unsigned long n = 0; n < 2000; n++) {
		snprintf(nb, sizeof nb, "%lu", n);
		if (zero_bits(tok, nb) < 12)
			ASSERT(!bst_challenge_verify_pow(&c, S_(tok), S_(nb), &a, now));
	}
	ASSERT(!bst_challenge_verify_pow(&c, S_(tok), S_(""), &a, now));
	ASSERT(!bst_challenge_verify_pow(&c, S_(tok), S_("1 2"), &a, now));
	snprintf(nb, sizeof nb, "%lu", good);
	/* tampered: a later expiry, another IP hash, a flipped MAC character */
	char t2[BST_CHALLENGE_TOKEN_MAX];
	strcpy(t2, tok);
	t2[0] = t2[0] == '9' ? '8' : (char)(t2[0] + 1);
	ASSERT(!bst_challenge_verify_pow(&c, S_(t2), S_(nb), &a, now));
	strcpy(t2, tok);
	char *d1 = strchr(t2, '.');
	d1[1] = d1[1] == 'a' ? 'b' : 'a';
	ASSERT(!bst_challenge_verify_pow(&c, S_(t2), S_(nb), &a, now));
	strcpy(t2, tok);
	size_t L = strlen(t2);
	t2[L - 1] = t2[L - 1] == '0' ? '1' : '0';
	ASSERT(!bst_challenge_verify_pow(&c, S_(t2), S_(nb), &a, now));
	ASSERT(!bst_challenge_verify_pow(&c, S_("garbage"), S_(nb), &a, now));
	ASSERT(!bst_challenge_verify_pow(&c, S_("1.2.3"), S_(nb), &a, now));
	/* a stricter difficulty than the token was made for does not change its MAC check */
	ASSERT(bst_challenge_verify_pow(&c, S_(tok), S_(nb), &a, now + 299));
	/* expired */
	ASSERT(!bst_challenge_verify_pow(&c, S_(tok), S_(nb), &a, now + 300));
	ASSERT(!bst_challenge_verify_pow(&c, S_(tok), S_(nb), &a, now + 100000));
	/* another key (a restart) knows nothing of it */
	uint8_t k2[BST_CHALLENGE_KEY_LEN];
	memcpy(k2, KEY, sizeof k2);
	k2[0] ^= 1;
	bst_challenge_use_key(k2);
	ASSERT(!bst_challenge_verify_pow(&c, S_(tok), S_(nb), &a, now));
	bst_challenge_use_key(KEY);
}

TEST(wrong_ip_prefix)
{
	bst_challenge_use_key(KEY);
	bst_challenge_cfg c = cfg(4);
	bst_ip a = ip("192.0.2.10"), other = ip("192.0.3.10"), v6 = ip("2001:db8:1:200::1"),
	       v6same = ip("2001:db8:1:2ff::9"), v6other = ip("2001:db8:1:300::1");
	uint64_t now = 1700000000;
	char tok[BST_CHALLENGE_TOKEN_MAX], nb[24], pass[BST_CHALLENGE_PASS_MAX];
	ASSERT(bst_challenge_issue(&c, &a, now, tok, sizeof tok) > 0);
	unsigned long exact;
	snprintf(nb, sizeof nb, "%lu", solve(tok, 4, &exact));
	ASSERT(bst_challenge_verify_pow(&c, S_(tok), S_(nb), &a, now));
	ASSERT(!bst_challenge_verify_pow(&c, S_(tok), S_(nb), &other, now));
	ASSERT(!bst_challenge_verify_pow(&c, S_(tok), S_(nb), &v6, now));
	ASSERT(bst_challenge_pass(&c, &a, now, pass, sizeof pass) > 0);
	ASSERT(!bst_challenge_cookie_valid(&c, S_(pass), &other, now));
	/* IPv6: bound to the /56 */
	ASSERT(bst_challenge_pass(&c, &v6, now, pass, sizeof pass) > 0);
	ASSERT(bst_challenge_cookie_valid(&c, S_(pass), &v6same, now));
	ASSERT(!bst_challenge_cookie_valid(&c, S_(pass), &v6other, now));
}

TEST(difficulty_bits)
{
	/* the check itself at exact boundaries, across a byte */
	uint8_t h[32];
	memset(h, 0xff, sizeof h);
	for (unsigned n = 0; n <= 20; n++) {
		memset(h, 0xff, sizeof h);
		memset(h, 0, n / 8);
		if (n % 8)
			h[n / 8] = (uint8_t)(0xff >> (n % 8));
		/* exactly n zero bits */
		ASSERT(bst_challenge_zero_bits(h, n));
		ASSERT(!bst_challenge_zero_bits(h, n + 1));
	}
	/* end to end: N = 9 crosses the first byte; a nonce with exactly 9 bits passes, one with 8
	 * does not */
	bst_challenge_use_key(KEY);
	bst_challenge_cfg c = cfg(9);
	bst_ip a = ip("192.0.2.77");
	uint64_t now = 1700000000;
	char tok[BST_CHALLENGE_TOKEN_MAX], nb[24];
	ASSERT(bst_challenge_issue(&c, &a, now, tok, sizeof tok) > 0);
	unsigned long exact9, exact8;
	(void)solve(tok, 9, &exact9);
	(void)solve(tok, 8, &exact8);
	ASSERT(exact9 != (unsigned long)-1 && exact8 != (unsigned long)-1);
	snprintf(nb, sizeof nb, "%lu", exact9);
	ASSERT(bst_challenge_verify_pow(&c, S_(tok), S_(nb), &a, now));
	snprintf(nb, sizeof nb, "%lu", exact8);
	ASSERT_EQ(zero_bits(tok, nb), 8);
	ASSERT(!bst_challenge_verify_pow(&c, S_(tok), S_(nb), &a, now));
}

TEST(cookie_tamper_and_expired)
{
	bst_challenge_use_key(KEY);
	bst_challenge_cfg c = cfg(4);
	bst_ip a = ip("198.51.100.5");
	uint64_t now = 1700000000;
	char pass[BST_CHALLENGE_PASS_MAX], p2[BST_CHALLENGE_PASS_MAX];
	ASSERT(bst_challenge_pass(&c, &a, now, pass, sizeof pass) > 0);
	ASSERT(bst_challenge_cookie_valid(&c, S_(pass), &a, now + 3599));
	ASSERT(!bst_challenge_cookie_valid(&c, S_(pass), &a, now + 3600)); /* expired */
	/* a later expiry under the same MAC */
	strcpy(p2, pass);
	p2[3] = p2[3] == '9' ? '8' : (char)(p2[3] + 1);
	ASSERT(!bst_challenge_cookie_valid(&c, S_(p2), &a, now));
	/* every MAC character flipped in turn */
	size_t L = strlen(pass);
	const char *dot = strchr(pass, '.');
	for (size_t i = (size_t)(dot - pass) + 1; i < L; i++) {
		strcpy(p2, pass);
		p2[i] = p2[i] == 'f' ? '0' : 'f';
		ASSERT(!bst_challenge_cookie_valid(&c, S_(p2), &a, now));
	}
	p2[0] = '\0';
	ASSERT(!bst_challenge_cookie_valid(&c, S_(""), &a, now));
	ASSERT(!bst_challenge_cookie_valid(&c, S_("1700003600"), &a, now));
	ASSERT(!bst_challenge_cookie_valid(&c, S_("x.y"), &a, now));
	/* a short MAC is not a prefix match */
	strcpy(p2, pass);
	p2[L - 2] = '\0';
	ASSERT(!bst_challenge_cookie_valid(&c, S_(p2), &a, now));
}

TEST(secret_rotation)
{
	bst_challenge_use_key(KEY);
	bst_challenge_cfg c = cfg(4);
	c.pass_ttl_s = 10000; /* longer than a generation, so only the secret decides */
	c.rotate_s = 1000;
	bst_ip a = ip("198.51.100.9");
	uint64_t t0 = 1700000000ull / 1000 * 1000 + 100; /* early in generation g */
	char pass[BST_CHALLENGE_PASS_MAX];
	ASSERT(bst_challenge_pass(&c, &a, t0, pass, sizeof pass) > 0);
	ASSERT(bst_challenge_cookie_valid(&c, S_(pass), &a, t0 + 500));	   /* g */
	ASSERT(bst_challenge_cookie_valid(&c, S_(pass), &a, t0 + 1500));   /* g + 1: the overlap */
	ASSERT(!bst_challenge_cookie_valid(&c, S_(pass), &a, t0 + 2000)); /* g + 2: gone */
}

/* challenge auto's flag (sec/attack.h): on at the threshold, kept through the hold under an
 * oscillating load, off after a quiet hold; forcing wins. */
TEST(attack_hold)
{
	static uint8_t mem[4096];
	memset(mem, 0, sizeof mem);
	if (bst_attack_bytes(2) > sizeof mem)
		abort();
	bst_attack_attach(mem, 2);
	bst_attack_cfg c = { .rps = 100, .block_rate = 0, .hold_s = 5 };
	bst_attack_state st;
	memset(&st, 0, sizeof st);
	uint64_t t = 1000000000ull;
	bst_attack_worker(0);
	ASSERT_EQ(bst_attack_sample(&c, &st, t), 0); /* the baseline */
	for (int i = 0; i < 50; i++)
		bst_attack_request();
	t += 1000000;
	ASSERT_EQ(bst_attack_sample(&c, &st, t), 0);
	ASSERT(!bst_attack_on());
	bst_attack_worker(1); /* the rate is across workers */
	for (int i = 0; i < 60; i++)
		bst_attack_request();
	bst_attack_worker(0);
	for (int i = 0; i < 60; i++)
		bst_attack_request();
	t += 1000000;
	ASSERT_EQ(bst_attack_sample(&c, &st, t), 1);
	ASSERT(bst_attack_on());
	for (int k = 0; k < 10; k++) { /* oscillating: one second above, one below */
		for (int i = 0; i < (k % 2 ? 10 : 200); i++)
			bst_attack_request();
		t += 1000000;
		ASSERT_EQ(bst_attack_sample(&c, &st, t), 0);
		ASSERT(bst_attack_on());
	}
	for (int s = 1; s < 5; s++) { /* quiet, but not for the whole hold */
		t += 1000000;
		ASSERT_EQ(bst_attack_sample(&c, &st, t), 0);
		ASSERT(bst_attack_on());
	}
	t += 1000000;
	ASSERT_EQ(bst_attack_sample(&c, &st, t), -1);
	ASSERT(!bst_attack_on());
	/* refusals alone can turn it on */
	c.block_rate = 20;
	for (int i = 0; i < 25; i++)
		bst_attack_refusal();
	t += 1000000;
	ASSERT_EQ(bst_attack_sample(&c, &st, t), 1);
	bst_attack_force(-1);
	ASSERT(!bst_attack_on());
	bst_attack_force(0);
	ASSERT(bst_attack_on());
}

TAP_MAIN()
