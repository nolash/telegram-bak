#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <zlib.h>

#include "error.h"
#include "std.h"

#define AUTH_KEY_LENGTH 8

unsigned int message_sequence;
unsigned char auth_key[AUTH_KEY_LENGTH];

/***
 * Pads the supplied blob up to a multiple of four bytes
 * It will pad in-place, overwriting up to 3 bytes after l
 *
 * \params l length of blob to pad
 * \params v blob which must have
 * \return new length
 */
int tgbk_pad(int l, char *v) {
	int r;

	r = (l % 4);
	if (r == 0) {
		return l;
	}
	r = 4 - r;
	memset(v+l, 0, r);
	return l + r;
}

/***
 * Unwraps string from serialized form
 *
 * \return the net size of the data
 * \todo handle lengths longer than 254
 */
int tgbk_string_unserialize(const unsigned char *v, int *t, int *l, unsigned char **zR, unsigned char **zO) {
	*l = char2int32(*v);
	*t = padsize(*l+1);

	memcpy(*zR, v+1, *l);
	
	if (zO != NULL) {
		memcpy(*zO, v+1+(*l), *t-*l-1);
	}
	return *l;
}

/***
 * Binary serialization of string according to MT Protocol 
 *
 * \param l string length
 * \param v string
 * \param zS output string, must be allocated to at least 4+c rounded up to nearest multiple of 4
 * \return number of bytes written, or -1 on error
 */
int tgbk_string_serialize(int l, const char *v, unsigned char **zS) {
	int c;
	int p;

	if (l > 254) {
		**zS = 254;
		memcpy(*zS+1, &l, 3);
		c = l+4;
		memcpy(*zS+4, v, l);
	} else {
		**zS = *((char*)&l);
		c = l+1;
		memcpy(*zS+1, v, l);
	}

	return tgbk_pad(c, *zS);
//	p = c%4;
//	if (p > 0) {
//		p=4-p;
//	}
//	memset(*zS+c, 0, p);
//	return p+c;
}

/***
 * Adds combinator to the start of the blob
 *
 * \param t combinator string
 * \param l length of message to encapsulate
 * \param v message 
 * \param zT output string, must be of at least size l+4 bytes
 * \return number of bytes written
 */
int tgbk_type_wrap(const char *t, int l, const unsigned char *v, unsigned char **zT) {
	uLong z;

	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, t, strlen(t));
	memcpy(*zT, &z, 4);
	memcpy(*zT+4, v, l);
	return l+4;
}

/***
 * Adds auth key, message id and message length to the message
 *
 * \param l length of message to encapsulate
 * \param v message blob
 * \param zM output string, must be of at least size l+20 bytes
 * \return number of bytes written, or -1 on error
 */
int tgbk_metadata_wrap(int l, const unsigned char *v, unsigned char **zM) {
	int r;
	long tm;
	long tmp;
	struct timespec ts;

	// get nanosec time for message id
	r = timespec_get(&ts, TIME_UTC);
	if (r == 0) {
		return -1;
	}
	tmp = ts.tv_nsec;
	memcpy((int*)&tm, &tmp, 4);
	tmp = ts.tv_sec;
	memcpy((int*)(&tm)+1, (int*)&tmp, 4);

	// write auth key
	memcpy(*zM, auth_key, AUTH_KEY_LENGTH);
	r = AUTH_KEY_LENGTH;

	// write message id
	memcpy(*zM+r, &tm, 8);
	r += 8;

	// write message body length
	memcpy(*zM+r, &l, 4);
	r += 4;

	// write message
	memcpy(*zM+r, v, l);	
	return l + r;
}

/***
 * Encapsulates a message with tcp transport header and crc sums 
 *
 * \param l length of message to encapsulate
 * \param v message
 * \param zT output string, must be of at least size l+12 bytes
 * \return number of bytes written
 */
int tgbk_transport_wrap(int l, const unsigned char *v, unsigned char **zT) {
	int z;
	int c;

	c = 0;
	z = l + 12;
	memcpy(*zT, &z, 4);
	c+=4;
	memcpy(*zT+c, &message_sequence, 4);
	c+=4;
	memcpy(*zT+c, v, l);
	c+=l;

	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, *zT, c);
	memcpy(*zT+c, &z, 4);

	message_sequence++;

	return c + 4;
}

/***
 * checks that message length reported in header is sane and crc is correct
 *
 * \param l length of wrapped message
 * \param v message
 * \return 0 on success, TGBK_ERR_CRC on crc mismatch, TGBK_ERR_LEN on wrong length
 */
int tgbk_transport_verify(int l, const unsigned char *v) {
	uLong z;

	if (*((int*)(v+4)) != l) {
		return TGBK_ERR_LEN;
	}
	z = crc32(0L, Z_NULL, 0);
	z = crc32(z, v, l-4);
	if (memcmp(&z, v+(l-4), 4)) {
		//fprintf(stderr, "CRCs do not match: our %x / their %x", z, *(int*)(buf+(r-4)));
		return TGBK_ERR_CRC;
	}

	return 0;
}

void tgbk_set_auth_key(unsigned char *k) {
	memcpy(auth_key, k, AUTH_KEY_LENGTH);
}

void tgbk_init() {
	memset(auth_key, 0, 8);
	message_sequence = 0;
}

