#ifndef TGBK_PRIMES_H_
#define TGBK_PRIMES_H_

int tgbk_pq(int n, char *src, int cap, unsigned char **one, int *one_n, unsigned char **two, int *two_n);
int tgbk_decompose(BIGNUM *n, BIGNUM **zOne, BIGNUM **zTwo);

#endif // TGBK_PRIMES_H_
