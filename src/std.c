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
