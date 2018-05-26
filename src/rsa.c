#include <stdio.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "rsa.h"

extern RSA *tgbk_rsa_pubkey;

int tgbk_havePubkey() {
	return tgbk_rsa_pubkey != NULL;
}

int tgbk_encrypt(const unsigned char *src, int l, unsigned char *zTo) {
	if (!tgbk_havePubkey()) {
		return 1;
	}
	fprintf(stderr, "encrypt rsa size is %d, len is %d\n", RSA_size(tgbk_rsa_pubkey), l);
	if (RSA_public_encrypt(l, src, zTo, tgbk_rsa_pubkey, RSA_PKCS1_OAEP_PADDING) == -1) {
		return 1;
	}
	return 0;
}

int tgbk_rsaPubkeyFromPemFile(const char *filename) {
	FILE *f;

	f = fopen(filename, "r");
	if (f == NULL) {
		return 1;
	}

	if (tgbk_rsa_pubkey != NULL) {
//		RSA_free(tgbk_rsa_pubkey);
		fprintf(stderr, "\nhad pubkey size: %d (datalen %d)\n", RSA_size(tgbk_rsa_pubkey), sizeof(tgbk_rsa_pubkey));

	}
	tgbk_rsa_pubkey = RSA_new();
	//tgbk_rsa_pubkey  = PEM_read_RSAPublicKey(f, NULL, NULL, NULL);
	if (PEM_read_RSAPublicKey(f, &tgbk_rsa_pubkey, NULL, NULL) == NULL) {
		fprintf(stderr, "failed to read PEM\n");
	}
	fprintf(stderr, "\nread pubkey size: %d (datalen %d)\n", RSA_size(tgbk_rsa_pubkey), sizeof(tgbk_rsa_pubkey));

	fclose(f);
	return 0;
}

int tgbk_rsaPubkeyToBin(char **zN, int *nN, char **zE, int *nE) {
	BIGNUM *bn;
	BIGNUM *be;
	char *n;
	char *e;

	if (!tgbk_havePubkey()) {
		return 1;
	}

	fprintf(stderr, "\nbefore pubkey size: %d (datalen %d)\n", RSA_size(tgbk_rsa_pubkey), sizeof(tgbk_rsa_pubkey));
	RSA_get0_key((const RSA*)tgbk_rsa_pubkey, (const BIGNUM**)&bn, (const BIGNUM**)&be, NULL);

	BN_bn2bin(bn, *zN);
	BN_bn2bin(be, *zE);
	*nN = BN_num_bytes(bn);
	*nE = BN_num_bytes(be);

	return 0;
}

void tgbk_free() {
	if (tgbk_rsa_pubkey != NULL) {
		RSA_free(tgbk_rsa_pubkey);
	}
}
