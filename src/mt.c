#include <stdlib.h>
#include <string.h>

/***
 * Binary serialization of string according to MT Protocol 
 *
 * \param c string byte count
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

	p = c%4;
	if (p > 0) {
		p=4-p;
	}
	memset(*zS+c, 0, p);
	return p+c;
}
