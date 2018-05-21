#include <stdio.h>

#include "rsa.h"

int main(int argc, char **argv) {
	char *n;
	char *e;
	int ln;
	int le;

	if (tgbk_rsaPubkeyFromPemFile(*(argv+1))) {
		fprintf(stderr, "couldn't read pem file %s\n", *(argv+1));
		return 1;
	}

	n = malloc(sizeof(char)*4096);
	e = malloc(sizeof(char)*4096);

	if (tgbk_rsaPubkeyToBin(&n, &ln, &e, &le)) {
		fprintf(stderr, "couldn't retrieve key\n");
		return 2;	
	}

	return 0;
}
