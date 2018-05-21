#include <stdio.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

extern RSA *tgbk_rsa_pubkey;

int tgbk_rsaPubkeyFromPemFile(const char *filename) {
	FILE *f;

	f = fopen(filename, "r");
	if (f == NULL) {
		return 1;
	}
	tgbk_rsa_pubkey = PEM_read_RSAPublicKey(f, NULL, NULL, NULL);
	fclose(f);
	return 0;
}

int tgbk_rsaPubkeyToBin(char **zN, int *nN, char **zE, int *nE) {
	BIGNUM *bn;
	BIGNUM *be;
	char *n;
	char *e;

	if (tgbk_rsa_pubkey == NULL) {
		return 1;
	}

	bn = BN_new();
	be = BN_new();

	RSA_get0_key(tgbk_rsa_pubkey, (const BIGNUM**)&bn, (const BIGNUM**)&be, NULL);

	BN_bn2bin(bn, *zN);
	BN_bn2bin(be, *zE);
	*nN = BN_num_bytes(bn);
	*nE = BN_num_bytes(be);

	BN_free(bn);
	BN_free(be);

	return 0;
}
