#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <zlib.h>

#include "primes.h"
#include "std.h"
#include "config.h"
#include "rsa.h"
#include "mt.h"

#define KEYDIR "keys"

#define TELEGRAM_HOST TELEGRAM_SERVER_TEST_1
#define TELEGRAM_PORT TELEGRAM_PORT_2


int find_pubkey(char *keydir, unsigned char *fingerprint);
int dump_buffer(char *fname, char *buf, int n);

// WIP
// a messy implementation of Telegram's MTProto API; first client auch msg
// (Code assumes little-endian arch. ints, crcs etc need to be converted if not)
int main(int argc, char **argv) {


	// result ints + iterators
	int r, i, j;

	// messages
	unsigned char b[1024]; // work buffer
	char msg[1024]; // send buffer
	char buf[1024]; // recv buffer
	char *rpccall_str;
	char *t, *u; // tmp char pointers
	int msglen;

	// inet + ipc
	char ip[16];
	short port;
	int sd; // socket fd
	struct addrinfo hints, *res, *p;

	struct timespec ts;
	long tm;
	long tmp;

	// zlib
	uLong z;

	// hashing
	SHA_CTX shactx;

	// local io
	int f;
	char *fname;
	char *keydir;

	// process input
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <keydir>", *argv);
		return 1;
	}
	keydir = *(argv+1);

	// command is crc32 of "<callname> [args:type].. = <Type>", converted to NBO
	rpccall_str = "req_pq_multi nonce:int128 = ResPQ";
	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, (const char*)rpccall_str, strlen(rpccall_str));

	// make a random nonce
	memset(b+512, 0, 16);
	r = RAND_bytes(b+512, 16);
	if (r == 0) {
		fprintf(stderr, "Failed to acquire rand bytes\n");
		return 1;
	}

	// get nanosec time 
	r = timespec_get(&ts, TIME_UTC);
	if (r == 0) {
		fprintf(stderr, "Failed to get 64bit time\n");
		return 1;
	}
	tmp = ts.tv_nsec;
	memcpy((int*)&tm, &tmp, 4);
	tmp = ts.tv_sec;
	memcpy((int*)(&tm)+1, (int*)&tmp, 4);

	// compose the message
	// It has four parts:
	// encapsulation head = tcp transport (https://core.telegram.org/mtproto#tcp-transport)
	// header = ...
	// payload = ....
	// encapsulation tail = checksum
	
	// first add the total length (encapsulation)
	r = 52;
	memcpy(msg, &r, 4);

	// sequence number 4 bytes (encapsulation) + auth key 8 bytes (header)
	// both can be zero since first message and not encrypted
	memset(msg+4, 0, 12);

	// message id = time
	memcpy(msg+16, &tm, 8);

	// length of payload
	msglen = 20;
	memcpy(msg+24, &msglen, 4);

	// rpc_pq api call (in crc form)
	// Telegram calls it "combinator"
	memcpy(msg+28, &z, 4);

	// our nonce
	memcpy(msg+32, b+512, 16);

	// add the crc32 of all previous added content at the end
	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, msg, 48);
	memcpy(msg+48, &z, 4);

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

	// connect and send data
	r = connect(sd, res->ai_addr, res->ai_addrlen);
	if (r != 0) {
		fprintf(stderr, "Can't connect: %s", strerror(errno));
		return 1;
	}
	r = send(sd, msg, 52, 0);
	if (r < 0) {
		fprintf(stderr, "Send error: %d", errno);
		close(sd);
		return 1;	
	} else if (r != 52) {
		fprintf(stderr, "Short send: %d", r);
		close(sd);
		return 1;	
	}

	// write send phase 1 to file
	fname = "1_send.bin";
	if (dump_buffer(fname, msg, 52)) {
		close(sd);
		return 1;
	}

	// receive data from server
	r = recv(sd, buf, 1024, 0);
	if (r <= 0) {
		fprintf(stderr, "No msg received: %s", strerror(errno));
		close(sd);
		return 1;
	}

	// write recv phase 1 to file
	fname = "1_recv.bin";
	if (dump_buffer(fname, buf, 104)) {
		close(sd);
		return 1;
	}

	// check server response length
	if (r != 104) {
		fprintf(stderr, "Server response should be 104 bytes, was %d", r);
		close(sd);
		return 1;
	}

	// server sends our nonce back. Check that it matches
	if (memcmp(buf+32, msg+32, 16)) {
		fprintf(stderr, "Nonces do not match!");
		close(sd);
		return 1;
	}
	memcpy(b+512+16, buf+48, 16); // copy the server nonce for later
		
	// last 4 bytes of server response is crc32 of message
	// verify it
	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, buf, r-4);
	if (memcmp(&z, buf+(r-4), 4)) {
		fprintf(stderr, "CRCs do not match: our %x / their %x", z, *(int*)(buf+(r-4)));
		close(sd);
		return 1;
	}

	// choose public key fingerprint from response
	// get number of keys	
	// \TODO flip on big endian system
	memcpy(&j, buf+80, 4);
	// iterate and match
	r = 0;
	j = 512 + 64; // offset for fingerprint
	for (i = 0; i < j*8; i+=8) {
		memcpy(b+j, buf+84+i, 8);
		if (!find_pubkey(keydir, b+j)) {
			r = 1;
			break;
		}
	}
	if (!r) {
		fprintf(stderr, "Unknown key fingerprint ");
		b[512+64+8] = 0x0;
		for (i = j; i < j+8; i++) {
			fprintf(stderr, "%02x", *(b+j));
		}
		fprintf(stderr, "\n");
		close(sd);
		return 1;
	}

	// solve pq challenge
	memset(b, 0, 72);
	memset(b+1020, 0, 4);
	b[1020] = buf[64];
	r = *((unsigned int*)(b+1020));
	memcpy(b, (buf+65), r);
	t = b+512+132;
	u = b+512+148;
	r = tgbk_pq(r, b, 32, (unsigned char**)&t, &i, (unsigned char**)&u, &j);
	if (r) {
		fprintf(stderr, "pq solve failed: %d\n", r);
		close(sd);
		return 1;
	}
	if (is_le()) {
		int32_rev((int*)t);
		int32_rev((int*)u);
	}
	memcpy(b+512+128, &i, 4);
	memcpy(b+512+144, &j, 4);

	// serialize the pq
	t = b+512+256+4;
	u = b+512+256+20;
	i = *((int*)(b+512+128));
	i = tgbk_string_serialize(i, b+512+132, (unsigned char**)&t);
        j = *((int*)(b+512+144));
	memcpy(b+512+256, &i, 4);
	j = tgbk_string_serialize(j, b+512+148, (unsigned char**)&u);
	memcpy(b+512+256+16, &j, 4);

	// build 
	rpccall_str = "p_q_inner_data pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 = P_Q_inner_data";
	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, (const char*)rpccall_str, strlen(rpccall_str));

	// TODO dynamic determine pq data lengths, for now assume 12 bytes for pq and 8 bytes for p and q (8 and 4 respectively plus 1 length byte, padded to multiple of 4)
	// TODO directly copy to correct offset of msg

	// combinator req_pq_inner_data
	memcpy(msg, &z, 4);

        // pq	
	memcpy(msg+4, &buf[64], 12);
	
	// p answer
	//msg[16] = 4;
	//memcpy(msg+17, &b[32], 4);
	memcpy(msg+16, t, i);

	// q answer
	//msg[24] = 4;
	//memcpy(msg+25, &b[64], 4);
	memcpy(msg+16+i, u, j);
	
	// client nonce and server nonce
	memcpy(msg+16+i+j, buf+32, 32);

	// save server nonce for later
	memcpy(b+512+16, buf+48, 16);

	// make a new nonce and copy
	memset(b, 0, 32);
	r = RAND_bytes(b, 32);
	if (r == 0) {
		fprintf(stderr, "Failed to acquire rand bytes\n");
		close(sd);
		return 1;
	}
	r = 16+i+j;
	memcpy(msg+r+32, b, 32);

	// add the crc32 of all previous added content at the end
//	z = crc32(0L, Z_NULL, 0);
//	z = crc32(z, msg, 100);
//	memcpy(msg+r+64, &z, 4);
//
	// write innerdata serialization to file
	r += 64;
	fname = "2_innerdata.bin";
	if (dump_buffer(fname, msg, r)) {
		close(sd);
		return 1;
	}

	// move to buffer, because we will build the msg in msg
	memcpy(buf, msg, r);

	
	// i and j are still the lengths of the serializations of p and q
	// plus auth + message id + combinator + nonces + fingerprint + (boxed) encrypted data
	i += j + 8 + 8 + 4 + 4 + 32 + 8 + 260;

	// build the message
	// initialize
	memset(msg, 0, 1024);
	
	// set length
	r = i + 12;
	memcpy(msg, &r, 4);

	// message sequence number
	r = 1;
	memcpy(msg+4, &r, 4);

	// get nanosec time 
	// = message id
	r = timespec_get(&ts, TIME_UTC);
	if (r == 0) {
		fprintf(stderr, "Failed to get 64bit time\n");
		return 1;
	}
	tmp = ts.tv_nsec;
	memcpy((int*)&tm, &tmp, 4);
	tmp = ts.tv_sec;
	memcpy((int*)(&tm)+1, (int*)&tmp, 4);
	memcpy(msg+16, &tm, 8);

	// message body length
	r = i - 20;
	memcpy(msg+24, &r, 4);

	// command
	rpccall_str = "req_DH_params nonce:int128 server_nonce:int128 p:string q:string public_key_fingerprint:long encrypted_data:string = Server_DH_Params";
	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, (const char*)rpccall_str, strlen(rpccall_str));
	memcpy(msg+28, &z, 4);

	// copy old nonce
	memcpy(msg+32, b+512, 16);

	// copy server nonce
	memcpy(msg+48, b+512+16, 16);

	// copy p and q
	i = *((int*)(b+512+256));
	memcpy(msg+64, b+512+256+4, i);
	j = *((int*)(b+512+256+16));
	memcpy(msg+64+i, b+512+256+20, j);

	i += j + 64;
	// copy fingerprint
	memcpy(msg+i, b+512+64, 8);
	i += 8;

	// create dh request
	SHA1_Init(&shactx);
	SHA1_Update(&shactx, buf, 96); // hash the data
	SHA1_Final(b, &shactx); 
	memcpy(b+SHA_DIGEST_LENGTH, msg, 96); // copy data
	// we're done with buf now, so we can discard it
	if (tgbk_encrypt(b, 214, buf)) { // maybe we should care about the remaining bytes, but for now use them as padding (the pkcs1 oaep padding adds another 41 bytes)
		r =  ERR_get_error();
		fprintf(stderr, "encryption failed: (%lu) %s", r, ERR_error_string(r, NULL));
		close(sd);
		return 1;
	}
	t = msg+i;
	r = tgbk_string_serialize(256, buf, (unsigned char**)&t);

	// add the crc32 of all previous added content at the end
	i += r;
	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, msg, i);
	memcpy(msg+i, &z, 4);

	// write msg serialization to file
	i += 4;
	fname = "2_send.bin";
	if (dump_buffer(fname, msg, i)) {
		close(sd);
		return 1;
	}

	// send to server
	r = send(sd, msg, i, 0);
	if (r < 0) {
		fprintf(stderr, "Send error: %d", errno);
		close(sd);
		return 1;	
	} else if (r != i) {
		fprintf(stderr, "Short send: %d", r);
		close(sd);
		return 1;	
	}

	// receive data from server
	r = recv(sd, buf, 1024, 0);
	if (r <= 0) {
		fprintf(stderr, "No msg received: %s", strerror(errno));
		close(sd);
		return 1;
	}

	// write recv phase 1 to file
	fname = "2_recv.bin";
	if (dump_buffer(fname, buf, r)) {
		close(sd);
		return 1;
	}

	tgbk_free();
	close(sd);
	// all done!
	return 0;
}
