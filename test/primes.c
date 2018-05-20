#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "primes.h"
#include "std.h"

int main() {
	int r;
	int i, j;
	char  *b;
	unsigned char *one;
	unsigned char *two;
	BIGNUM *x;
	BIGNUM *y;
	BIGNUM *p;
	BN_CTX *ctx;

	p = BN_new();
	BN_hex2bn(&p, "17ED48941A08F981");

	tgbk_decompose(p, &x, &y);

	b = BN_bn2dec(x);
	printf("x: %s\n", b);
	OPENSSL_free(b);

	b = BN_bn2dec(y);
	printf("y: %s\n", b);
	OPENSSL_free(b);

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	BN_mul(x, x, y, ctx);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	r = BN_cmp(x, p);

	BN_free(x);
	BN_free(y);
	BN_free(p);

	if (r != 0) {
		return 1;
	}

	b = malloc(sizeof(char)*8);
	one = malloc(sizeof(unsigned char)*6);
	two = malloc(sizeof(unsigned char)*6);
	memset(one, 0, 6);
	memset(two, 0, 6);

	b[0] = 0x17;
	b[1] = 0xed;
	b[2] = 0x48;
	b[3] = 0x94;
	b[4] = 0x1a;
	b[5] = 0x08;
	b[6] = 0xf9;
	b[7] = 0x81;

	tgbk_pq(8, b, 6, &one, &i, &two, &j);
	
	if (i != 4 || j != 4) {
		fprintf(stderr, "expected both return values length 4, was %d and %d\n", i, j);
		return 1;
	}

	if (is_le()) {
		int32_rev((int*)one);
		int32_rev((int*)two);
	}

	printf("x: %d\n", *((int*)one));
	printf("y: %d\n", *((int*)two));

	free(two);
	free(one);
	free(b);

	return 0;
}
