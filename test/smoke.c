#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include "std.h"
#include "mt.h"
#include "config.h"
#include "primes.h"
#include "rsa.h"

#define TELEGRAM_HOST TELEGRAM_SERVER_TEST_1
#define TELEGRAM_PORT TELEGRAM_PORT_2

int find_pubkey(char *keydir, unsigned char *fingerprint);
char* bin2hex(int l, const unsigned char *v, char **zH);
int dump_buffer(char *fname, char *buf, int n);

int main(int argc, char **argv) {
	int i;
	int j;
	int r;
	int n;
	int c;

	unsigned char *t;
	unsigned char *u;
	unsigned char *b;

	unsigned char *buf_out;
	unsigned char *buf_in;

	unsigned char firstnoncelocal[16];
	unsigned char lastnoncelocal[32];
	unsigned char nonceremote[16];
	unsigned char fingerprint[8];

	// sockets
	char ip[16];
	short port;
	int sd; // socket fd
	struct addrinfo hints, *res;

	// iovars
	const char *keydir;
	char *fname;

	// crypt
	SHA_CTX shactx;

	// setup
	b = malloc(sizeof(char)*1024);
	buf_in = malloc(sizeof(char)*4096);
	buf_out = malloc(sizeof(char)*4096);

	// process input
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <keydir>", *argv);
		return 1;
	}
	keydir = *(argv+1);

	// set up socket
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_NUMERICSERV;
	r = getaddrinfo(TELEGRAM_HOST, TELEGRAM_PORT, &hints, &res);
	if (r != 0) {
		fprintf(stderr, "Can't create socket: %s", strerror(errno));
		return 1;
	}
	sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	// connect
	r = connect(sd, res->ai_addr, res->ai_addrlen);
	if (r != 0) {
		fprintf(stderr, "Can't connect: %s", strerror(errno));
		return 1;
	}

	//
	// PHASE 1
	// Send pq request to server
	//
	
	// make a random nonce
	r = RAND_bytes(firstnoncelocal, 16);
	if (r == 0) {
		fprintf(stderr, "Failed to acquire rand bytes\n");
		return 1;
	}

	memcpy(b, firstnoncelocal, 16);
	n = tgbk_type_wrap(TGBK_CMD_REQ_PQ, 16, b, &buf_out);
	n = tgbk_metadata_wrap(n, buf_out, &b);
	n = tgbk_transport_wrap(n, b, &buf_out);

	// send data
	r = send(sd, buf_out, n, 0);
	if (r < 0) {
		fprintf(stderr, "Send error: %d", errno);
		close(sd);
		return 1;	
	} else if (r != n) {
		fprintf(stderr, "Short send: %d of %d", r, n);
		close(sd);
		return 1;	
	}

	// write send phase 1 to file
	fname = "1_send.bin";
	if (dump_buffer(fname, buf_out, n)) {
		close(sd);
		return 1;
	}

	// receive data from server
	r = recv(sd, buf_in, 4096, 0);
	if (r <= 0) {
		fprintf(stderr, "No msg received: %s", strerror(errno));
		close(sd);
		return 1;
	}

	// write recv phase 1 to file
	fname = "1_recv.bin";
	if (dump_buffer(fname, buf_in, r)) {
		close(sd);
		return 1;
	}

	// server sends our nonce back. Check that it matches
	if (memcmp(buf_in+32, firstnoncelocal, 16)) {
		fprintf(stderr, "nonce does not match!");
		close(sd);
		return 1;
	}

	// copy the server nonce for later
	memcpy(nonceremote, buf_in+48, 16); 

	// verify the reply
	if (r = tgbk_transport_verify(r, buf_in)) {
		fprintf(stderr, "server reply corrupt (%d)\n", r);
		close(sd);
		return 1;
	}

	//
	// PHASE 2.1
	// process input from server
	//
	
	memset(buf_out, 0, 4096);
	memset(b, 0, 1024);
	
	// choose public key fingerprint from response
	// get number of keys	
	// \TODO flip on big endian system
	memcpy(&c, buf_in+80, 4);
	// iterate and match
	r = 0;
	for (i = 0; i < c*8; i+=8) {
		memcpy(fingerprint, buf_in+84+i, 8);
		if (!find_pubkey((char*)keydir, fingerprint)) {
			r = 1;
			break;
		}
	}
	if (!r) {
		fprintf(stderr, "Unknown key fingerprint %s\n", bin2hex(8, fingerprint, (char**)&b));
			
		close(sd);
		return 1;
	}

	// solve pq challenge
	
	// extract the pq number
	tgbk_string_unserialize(buf_in+64, &n, &c, &b, NULL);
	
	// write the original pq string to buf_out
	memcpy(buf_out, buf_in+64, n);
	//c = char2int32(*(buf_in+64);

	// copy the pq data to work buffer, and point to output positions
	//memcpy(b, buf_in+65, c);

	// get the length of the data field (it pads to four)
	// should be safe since fingerprint will be a low value
	// copy that length data (the original pq number) to the message buffer
	//i = 4 - ((c+1) % 4);
	//r = c + i + 1;
	//memcpy(buf_out, buf_in+64, r);

	// save the length of the pq data field
	// (it is our offset for buf_out)
	//memset(b+1020, 0, 4);
	//memcpy(b+1020, &r, 4);

	// pq decomposition
	// i = net length of p, pointed to by *t
	// j = net length of q, pointed to by *u
	t = b+128;
	u = b+256;
	r = tgbk_pq(c, b, 32, (unsigned char**)&t, &i, (unsigned char**)&u, &j);
	if (r) {
		fprintf(stderr, "pq solve failed: %d\n", r);
		close(sd);
		return 1;
	}
	// TODO we're assuming 4 bytes numbers here, probably dangerous and should be bignum (this should be handled inside the function)
	if (is_le()) {
		int32_rev((int*)t);
		int32_rev((int*)u);
	}

	// serialize the pq to message format
	// retrieve the previously saved buf_out offset
	//c = *((int*)(b+1020));

	// serialize directly to buf_out
	c = n;
	t = buf_out+n;
	n += tgbk_string_serialize(i, b+128, (unsigned char**)&t);
	u = buf_out+n;
	n += tgbk_string_serialize(j, b+256, (unsigned char**)&u);

	// then append the nonces
	memcpy(buf_out+n, firstnoncelocal, 16);
	n += 16;
	memcpy(buf_out+n, nonceremote, 16);
	n += 16;

	// create and append new nonce
	r = RAND_bytes(buf_out+n, 32);
	if (r == 0) {
		fprintf(stderr, "Failed to acquire rand bytes for second nonce\n");
		close(sd);
		return 1;
	}
	n += 32;

	// wrap to boxed type
	n = tgbk_type_wrap(TGBK_CMD_PQ_INNER_DATA, n, buf_out, &b);
	memcpy(buf_out, b, n);

	// write innerdata serialization to file
	fname = "2_innerdata.bin";
	if (dump_buffer(fname, buf_out, n)) {
		close(sd);
		return 1;
	}
	
	//
	// PHASE 2.2
	// create message with encrypted payload and send
	//

	// copy to work buffer, save length
	// clean buf_out
	//memcpy(b+1020, &c, 4);
	memcpy(b, buf_out, n);
	memset(buf_out, 0, 4096);
	r = n;
	// retrieve the offset of the p and q
	//r = *((int*)(buf+1020));

	// copy the two nonces
	n = 32;
	i = r-64;
	memcpy(buf_out, b+i, n);

	// copy the p and q
	i = r-64-4-c; // length 
	j = c+4; // c is still offset of p and q in b, now prefixed by 4 for command
	memcpy(buf_out+n, b+j, i); // copy to buf_out after nonces, length of p+q, length
	n += i; // move the offset

	// copy the fingerprint
	memcpy(buf_out+n, fingerprint, 8);
	n+=8;

	SHA1_Init(&shactx);
	SHA1_Update(&shactx, b, r); // hash the data, r saves the total length the pq_inner_data
	SHA1_Final(b+512, &shactx);  // write the hash
	memcpy(b+512+SHA_DIGEST_LENGTH, b, r); // copy data
	if (tgbk_encrypt(b+512, 214, b)) { // maybe we should care about the remaining bytes, but for now use them as padding (the pkcs1 oaep padding adds another 41 bytes)
		r =  ERR_get_error();
		fprintf(stderr, "encryption failed: (%lu) %s", r, ERR_error_string(r, NULL));
		close(sd);
		return 1;
	}
	t = buf_out+n;
	n += tgbk_string_serialize(256, b, (unsigned char**)&t);

	n = tgbk_type_wrap(TGBK_CMD_REQ_DH_PARAMS, n, buf_out, &b);
	n = tgbk_metadata_wrap(n, b, &buf_out);
	n = tgbk_transport_wrap(n, buf_out, &b);
	memcpy(buf_out, b, n);

	// write innerdata serialization to file
	fname = "2_send.bin";
	if (dump_buffer(fname, buf_out, n)) {
		close(sd);
		return 1;
	}

	// send to server
	r = send(sd, buf_out, n, 0);
	if (r < 0) {
		fprintf(stderr, "Send error: %d", errno);
		close(sd);
		return 1;	
	} else if (r != n) {
		fprintf(stderr, "Short send: %d", r);
		close(sd);
		return 1;	
	}

	// receive data from server
	r = recv(sd, buf_in, 4096, 0);
	if (r <= 0) {
		fprintf(stderr, "No msg received: %s", strerror(errno));
		close(sd);
		return 1;
	}

	// write recv phase 1 to file
	fname = "2_recv.bin";
	if (dump_buffer(fname, buf_in, r)) {
		close(sd);
		return 1;
	}

	tgbk_free();

	// clean up
	close(sd);
	free(b);
	free(buf_out);
	free(buf_in);
	return 0;
}
