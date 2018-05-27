#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

#include <openssl/sha.h>
#include <zlib.h>

#include "rsa.h"
#include "mt.h"

int string_unserialize() {
	int i;
	unsigned char *test;
	unsigned char *data;
	unsigned char *overflow;
	unsigned char zero[12];
	int gross;
	int net;

	test = malloc(sizeof(test)*12);
	data = malloc(sizeof(test)*12);
	overflow = malloc(sizeof(test)*12);

	for (i = 0; i < sizeof(test); i++) {
		test[i] = i;
	}
	memset(zero, 0, 12);
	memset(overflow, 0, 12);
	memset(data, 0, 12);
	test[0] = 3;
	tgbk_string_unserialize(test, &gross, &net, &data, &overflow);
	if (gross != 4 || net != 3) {
		fprintf(stderr, "testlength 3: expected gross/net 4/3, got %d/%d\n", gross, net);
		free(overflow);
		free(data);
		free(test);
		return 1;
	} else if (memcmp(data, test+1, 3)) {
		fprintf(stderr, "testlength 3: unexpected data\n");
		free(overflow);
		free(data);
		free(test);
		return 1;
	} else if (memcmp(overflow, zero, 12)) { 
		fprintf(stderr, "testlength 3: unexpected overflow data\n");
		free(overflow);
		free(data);
		free(test);
		return 1;
	}

	memset(data, 0, 12);
	test[0] = 4;
	tgbk_string_unserialize(test, &gross, &net, &data, &overflow);
	if (gross != 8 || net != 4) {
		fprintf(stderr, "testlength 4: expected gross/net 8/4, got %d/%d\n", gross, net);
		free(overflow);
		free(data);
		free(test);
		return 1;
	} else if (memcmp(data, test+1, 4)) {
		fprintf(stderr, "testlength 4: unexpected data\n");
		free(overflow);
		free(data);
		free(test);
		return 1;
	} else if (memcmp(overflow, test+5, 3)) { 
		fprintf(stderr, "testlength 4: unexpected overflow data\n");
		free(overflow);
		free(data);
		free(test);
		return 1;
	}

	memset(overflow, 0, 12);
	memset(data, 0, 12);
	test[0] = 5;
	tgbk_string_unserialize(test, &gross, &net, &data, &overflow);
	if (gross != 8 || net != 5) {
		fprintf(stderr, "testlength 5: expected gross/net 8/5, got %d/%d\n", gross, net);
		free(overflow);
		free(data);
		free(test);
		return 1;
	} else if (memcmp(data, test+1, 5)) {
		fprintf(stderr, "testlength 5: unexpected data\n");
		free(overflow);
		free(data);
		free(test);
		return 1;
	} else if (memcmp(overflow, test+6, 2)) { 
		fprintf(stderr, "testlength 5: unexpected overflow data\n");
		free(overflow);
		free(data);
		free(test);
		return 1;
	}

	free(overflow);
	free(data);
	free(test);

	return 0;
}


int string_serialize() {
	int r, l;
	unsigned char *out;
	char *tests[2] = {
		"test",
		"wgrnwgrnwgnwgnregnuegniueangrianegrneaigreagineaigniagriaginaiuganuganugnaininingrieakenaknakngakenkengkangkangkangrkaengrkaenngkangkangrkeangrkeangkaengrkanngkaengkangkangkaengkaengkangkaengkaengkankangkangkangkaengkaengkaengkaengkaengkeaaenkearngkeanknakgrakrguankrn",
	};

	out = malloc(sizeof(char)*512);	
	l = (int)strlen(tests[0]);
	r = tgbk_string_serialize(l, tests[0], &out);
	if (r != 8) {
		return 1;
	} else if (*out != 4) {
		return 2;
	} else if (*(out+5) != 0 || *(out+6) != 0 || *(out+7) != 0) {
		return 3;	
	}

	l = (int)strlen(tests[1]);
	r = tgbk_string_serialize(l, tests[1], &out);
	if (r != 272) {
		return 4;
	} else if (*out != 254) {
		return 5;	
	} else {
		r = 0;
		memcpy(&r, out+1, 3);
		if (r != 268) {
			return 6;
		}
	}
	free(out);
	return 0;
}


int find_pubkey(char *keydir, unsigned char *fingerprint) {

	// io
	DIR *dp;
	struct dirent *de;

	// hasher
	SHA_CTX shactx;
	unsigned char *md = malloc(sizeof(char)*SHA_DIGEST_LENGTH);
	unsigned char *b = malloc(sizeof(char)*1024);

	// find the correct rsa public key
	memset(b, 0, 1024);
	
	dp = opendir(keydir);
	if (dp == NULL) {
		free(b);
		free(md);
		return 1;
	}

	while (de = readdir(dp)) {
		char *n;
		char *e;
		unsigned char *p;
		int nlen;
		int elen;
		int dl;
		int l;
		char fullpath[1024];
	      
	       	n = malloc(sizeof(char)*4096);	
	       	e = malloc(sizeof(char)*4096);	
		dl = strlen(de->d_name);
		strcpy(fullpath, keydir);
		*(fullpath+strlen(keydir)) = 0x2f;

		if (!strcmp((de->d_name)+(dl-3), "rsa")) {
			fprintf(stderr, "processing %s\n", de->d_name);
			strcpy(fullpath+strlen(keydir)+1, de->d_name);
			if (tgbk_rsaPubkeyFromPemFile(fullpath)) {
				closedir(dp);
				free(b);
				free(md);
				return 2;
			}
			if (tgbk_rsaPubkeyToBin(&n, &nlen, &e, &elen)) {
				closedir(dp);
				free(b);
				free(md);
				return 3;
			}

			l = 0;
			l += tgbk_string_serialize(nlen, n, &b);
			p = b+l;
			l += tgbk_string_serialize(elen, e, &p);
			SHA1_Init(&shactx);
			SHA1_Update(&shactx, b, l);
			SHA1_Final(md, &shactx);
		
			int i;
			fprintf(stderr, "\nHASH:\n");
			for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
				fprintf(stderr, "%02x", (unsigned int)*(md+i));  
			}
			fprintf(stderr, "\nDATA:\n");
			for (i = 0; i < l; i++) {
				fprintf(stderr, "%02x", *(b+i));  
			}
			fprintf(stderr, "\n\n");

			if (!memcmp(fingerprint, (unsigned int*)(md+SHA_DIGEST_LENGTH-TGBK_FINGERPRINT_SIZE), 8)) {
				fprintf(stderr, "\nMATCH!!!! size: %d\n");
				return 0;
			}
		}
		free(n);
		free(e);
	}
	closedir(dp);
	free(b);
	free(md);

	return 1;	
}

int dump_buffer(char *fname, char *buf, int n) {
	int f, e, r;

	e = 0;
	f = open(fname, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
	if (f == -1) {
		fprintf(stderr, "Could not open output file: %s: %d", fname, errno);
		e = errno;
	}
	r = write(f, buf, n);
	if (r!= n) {
		e = errno;
		fprintf(stderr, "Short write to %s: %d", fname, errno);
		close(f);
	}
	close(f);
	return e;
}

/***
 * Convert a byte sequence to hex string
 *
 * \param l length of bytes
 * \param v bytes to hexify
 * \param zH output string, must hold at least l*2+1 bytes
 * \return pointer to hex string
 * \todo write without using sprintf
 */
char* bin2hex(int l, const unsigned char *v, char **zH) {
	int i;
	int j;

	for (i = 0; i < l; i++) {
		j = i * 2;
		sprintf(*zH+j, "%02x", *(v+i));
	}
	*(zH+j) = 0x0;
	return *zH;
}
