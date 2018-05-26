#ifndef TGBK_RSA_H_
#define TGBK_RSA_H_

#include <openssl/rsa.h>

RSA *tgbk_rsa_pubkey;

int tgbk_rsaPubkeyFromPemFile(const char *filename);
int tgbk_rsaPubkeyToHex(char **zN, char **zE);
int tgbk_rsaPubkeyToBin(char **zN, int *nN, char **zE, int *nE);
int tgbk_havePubkey();
int tgbk_encrypt(const unsigned char *src, int l, unsigned char *zTo);
void tgbk_free();

#endif // TGBK_RSA_H_
