#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char* bin2hex(int l, const unsigned char *v, char **zH);
int string_serialize();
int find_pubkey(char *keydir, unsigned char *fingerprint);
int dump_buffer(char *fname, char *buf, int n);

int main() {
	int r;
	const unsigned char data[] = {0x01, 0x02, 0x03};
	char *p;
	char *b;

	// test bin2hex
	b = malloc(sizeof(char)*32);
	b = bin2hex(3, data, &b);
	p = "010203";
	if (strcmp(b, p)) {
		fprintf(stderr, "bin2hex expected %s, got %s", b, p);
		return 1;
	}

	if (r = string_serialize()) {
		return r;
	} 
	return find_pubkey("keys", NULL);
}
