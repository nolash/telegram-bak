#include "std.h"

void int32_rev(int *n) {
	char *p;
	char t;

	p = (char*)n;
	t=*(p+3);
	*(p+3)=*p;
	*p = t;
	t = *(p+1);
	*(p+1)=*(p+2);
	*(p+2)=t;
}


// check for little endian
int is_le() {
	short s;
	char *p;

	s = 1;
	p = (char*)&s;
	if (*p & 1) {
		return 1;
	}
	return 0;
}

int char2int32(const char n) {
	char b[4];

	if (is_le()) {
		b[0] = n;
	} else {
		b[3] = n;
	}
	return (int)*b;
}

int padsize(int c) {
	int r;	

	r = c % 4;
	if (r == 0) {
		return c;
	}
	return c + (4-r);
}
