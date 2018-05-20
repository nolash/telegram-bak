#ifndef TELEGRAM_BAK_PRIMES_
#define TELEGRAM_BAK_PRIMES_

int tgbk_pq(int n, char *src, int cap, unsigned char **one, int *one_n, unsigned char **two, int *two_n);
int tgbk_decompose(BIGNUM *n, BIGNUM **zOne, BIGNUM **zTwo);

#endif // TELEGRAM_BAK_PRIMES_
