SRCDIR=./src
TESTDIR=./test
BUILDDIR=./build
INCLUDES=-I$(SRCDIR)
obj: 
	$(CC) $(INCLUDES) -g3 -c $(SRCDIR)/primes.c -o $(SRCDIR)/primes.o
	$(CC) $(INCLUDES) -g3 -c $(SRCDIR)/std.c -o $(SRCDIR)/std.o

test: obj
	$(CC) $(INCLUDES) -g3 -c $(TESTDIR)/primes.c -o $(TESTDIR)/test_primes.o
	$(CC) $(INCLUDES) -g3 -o $(BUILDDIR)/primes_bin $(TESTDIR)/test_primes.o $(SRCDIR)/primes.o $(SRCDIR)/std.o -lcrypto

.PHONY: clean

clean:
	rm -rf *.o *_bin
