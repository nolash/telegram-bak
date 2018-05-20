#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>
#include <zlib.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>

#include "primes.h"
#include "std.h"
#include "config.h"

#define TELEGRAM_HOST TELEGRAM_SERVER_TEST_1
#define TELEGRAM_PORT TELEGRAM_PORT_2

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

// a messy implementation of Telegram's MTProto API; first client auch msg
// (Code assumes little-endian arch. ints, crcs etc need to be converted if not)
int main() {

	// result ints + iterators
	int r, i, j;

	// messages
	char b[256]; // work buffer
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

	// local io
	int f;
	char *fname;

	// command is crc32 of "<callname> [args:type].. = <Type>", converted to NBO
	rpccall_str = "req_pq_multi nonce:int128 = ResPQ";
	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, (const char*)rpccall_str, strlen(rpccall_str));

	// make a random nonce
	memset(b, 0, 16);
	r = RAND_bytes(b, 16);
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
	memcpy(msg+32, b, 16);

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
		
	// last 4 bytes of server response is crc32 of message
	// verify it
	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, buf, r-4);

	if (memcmp(&z, buf+(r-4), 4)) {
		fprintf(stderr, "CRCs do not match: our %x / their %x", z, *(int*)(buf+(r-4)));
		close(sd);
		return 1;
		
	}

	// TODO choose public key fingerprint from response

	// write phase 1 to file
	fname = "1_recv.bin";
	if (dump_buffer(fname, buf, 104)) {
		close(sd);
		return 1;
	}

	// solve pq challenge
	memset(b, 0, 72);
	r = buf[56];
	memcpy(b, &buf[56], r);
	t = &b[32];
	u = &b[64];
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

	// build 
	rpccall_str = "p_q_inner_data pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 = P_Q_inner_data";
	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, (const char*)rpccall_str, strlen(rpccall_str));

	// TODO dynamic determine pq data lengths, for now assume 12 bytes for pq and 8 bytes for p and q (8 and 4 respectively plus 1 length byte, padded to multiple of 4)
	
	// length of request
	r = 108;
	memset(msg, 0, r);
	memcpy(msg, (char*)&r, 4);

	// packet sequence number
	r = 1;
	memcpy(msg+4, (char*)&r, 4);

	// combinator req_pq_inner_data
	memcpy(msg+8, &z, 4);

        // pq	
	memcpy(msg+12, &buf[64], 12);
	
	// p answer
	msg[24] = 4;
	memcpy(msg+25, &b[32], 4);

	// q answer
	msg[32] = 4;
	memcpy(msg+33, &b[64], 4);
	
	// client nonce and server nonce
	memcpy(msg+40, &buf[32], 32);

	// make a new nonce
	memset(b, 0, 32);
	r = RAND_bytes(b, 32);
	if (r == 0) {
		fprintf(stderr, "Failed to acquire rand bytes\n");
		close(sd);
		return 1;
	}

	memcpy(msg+72, b, 32);

	// add the crc32 of all previous added content at the end
	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, msg, 112);
	memcpy(msg+104, &z, 4);

	// write innerdata serialization to file
	fname = "2_innerdata.bin";
	if (dump_buffer(fname, msg, 108)) {
		close(sd);
		return 1;
	}

	close(sd);
	// all done!
	return 0;
}
