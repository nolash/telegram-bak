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

#define TELEGRAM_HOST "149.154.167.50"
#define TELEGRAM_PORT "80"

// a messy implementation of Telegram's MTProto API; first client auch msg
// (Code assumes little-endian arch. ints, crcs etc need to be converted if not)
int main() {
	int r;
	char b[16];
	char msg[52];
	char ip[16];
	char buf[1024];
	short port;
	int msglen;
	struct timespec ts;
	long t;
	long tmp;
	uLong z;
	FILE *f;
	int s;

	struct addrinfo hints, *res, *p;

	// command is crc32 of "<callname> [args:type].. = <Type>", converted to NBO
	const char *rpccall_req_pq_str = "req_pq nonce:int128 = ResPQ";
	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, rpccall_req_pq_str, strlen(rpccall_req_pq_str));

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
	memcpy((int*)&t, &tmp, 4);
	tmp = ts.tv_sec;
	memcpy((int*)(&t)+1, (int*)&tmp, 4);

	// compose the message
	// total length (encapsulation)
	r = 52;
	memcpy(msg, &r, 4);

	// sequence number (encapsulation) + auth key (header)
	// both can be zero since first message and not encrypted
	memset(msg+4, 0, 12);

	// message id = time
	memcpy(msg+16, &t, 8);

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
	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	// connect and send data
	r = connect(s, res->ai_addr, res->ai_addrlen);
	if (r != 0) {
		fprintf(stderr, "Can't connect: %s", strerror(errno));
		return 1;
	}
	send(s, msg, 52, 0);

	// receive data from server
	r = recv(s, buf, 1024, 0);
	close(s);
	if (r <= 0) {
		fprintf(stderr, "No msg received: %s", strerror(errno));
		return 1;
	}

	// check server response length
	if (r != 96) {
		fprintf(stderr, "Server response should be 96 bytes, was %d", r);
		return 1;
	}

	// server sends our nonce back. Check that it matches
	if (memcmp(buf+32, msg+32, 16)) {
		fprintf(stderr, "Nonces do not match!");
		return 1;
	}
		
	// last 4 bytes of server response is crc32 of message
	// verify it
	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, buf, r-4);

	if (memcmp(&z, buf+(r-4), 4)) {
		fprintf(stderr, "CRCs do not match: our %x / their %x", z, *(int*)(buf+(r-4)));
		return 1;
		
	}

	// all done!
	return 0;
}
