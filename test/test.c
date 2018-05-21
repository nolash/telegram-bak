#include <stdlib.h>

int string_serialize();
int find_pubkey(char *keydir, unsigned char *fingerprint);
int dump_buffer(char *fname, char *buf, int n);

int main() {
	int r;
	if (r = string_serialize()) {
		return r;
	} 
	return find_pubkey("keys", NULL);
}
