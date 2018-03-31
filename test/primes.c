#include <openssl/bn.h>

#include "primes.h"
#include <stdio.h>


int main() {
	int r;
	char  *b;
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
	return 0;

}
