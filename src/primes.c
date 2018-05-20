#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "primes.h"

int tgbk_pq(int n, char *src, int cap, unsigned char **one, int *one_n, unsigned char **two, int *two_n) {
	int r;
	BIGNUM *bn_src;
	BIGNUM *bn_one;
	BIGNUM *bn_two;

	bn_src = BN_new();
	BN_bin2bn(src, n, bn_src);
	if (bn_src == NULL) {
		return 1;
	}
	tgbk_decompose(bn_src, &bn_one, &bn_two);

	*one_n = BN_bn2bin(bn_one, *one);
	*two_n = BN_bn2bin(bn_two, *two);

	BN_free(bn_src);
	BN_free(bn_one);
	BN_free(bn_two);
}

// rho algorithm for decomposing into two primes
// https://stackoverflow.com/questions/31953836/decompose-a-number-into-2-prime-co-factors/31978350#31978350
int tgbk_decompose(BIGNUM *n, BIGNUM **zOne, BIGNUM **zTwo) {
	BIGNUM *x;
	BIGNUM *y;
	BIGNUM *c;
	BIGNUM *g;
	BIGNUM *minusone;
	BN_CTX *ctx;

	int i;
	unsigned char *b;
	unsigned short s1, s2;

	ctx = BN_CTX_new();

	x = BN_new();
	c = BN_new();
	g = BN_new();

	b = malloc(sizeof(6));
	if (!RAND_bytes(b, 6)) {
		return 1;
	}

	*(b+2) = 0;
	*(b+5) = 0;
	*(b+1) &= ((1 << 2) - 1); // little endian
	*(b+4) = *(b+1);

	s1 = *((unsigned short*)b);
	s2 = *((unsigned short*)(b+3));

	memset(b, 0, 6);
	sprintf(b, "%hu", s1);
	BN_dec2bn(&x, b);

	sprintf(b, "%hu", s2);
	BN_dec2bn(&c, b);
	free(b);

	y = BN_dup(x);
	BN_dec2bn(&g, "1");

	minusone = BN_new();
	BN_dec2bn(&minusone, "-1");

	BN_CTX_start(ctx);
	while (BN_is_one(g)) {
		BIGNUM *t;

		BN_mod_mul(x, x, x, n, ctx);
		BN_add(x, x, c);
		BN_mod(x, x, n, ctx);

		BN_mod_mul(y, y, y, n, ctx);
		BN_add(y, y, c);
		BN_mod(y, y, n, ctx);

		BN_mod_mul(y, y, y, n, ctx);
		BN_add(y, y, c);
		BN_mod(y, y, n, ctx);

		t = BN_CTX_get(ctx);
		BN_sub(t, x, y);
		if (BN_is_negative(t)) {
			BN_mul(t, t, minusone, ctx);
		}
		BN_gcd(g, t, n, ctx);
	}
	
	BN_div(x, NULL, n, g, ctx);
	*zOne = BN_dup(g);
	*zTwo = BN_dup(x);

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	BN_free(x);
	BN_free(y);
	BN_free(c);
	BN_free(g);
	
	return 0;	
}
