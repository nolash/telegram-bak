SRCDIR=./src
TESTDIR=./test
BUILDDIR=./build
INCLUDES=-I$(SRCDIR) -I$(TESTDIR)
obj: 
	$(CC) $(INCLUDES) -g3 -c $(SRCDIR)/primes.c -o $(SRCDIR)/primes.o
	$(CC) $(INCLUDES) -g3 -c $(SRCDIR)/std.c -o $(SRCDIR)/std.o
	$(CC) $(INCLUDES) -g3 -c $(SRCDIR)/rsa.c -o $(SRCDIR)/rsa.o
	$(CC) $(INCLUDES) -g3 -c $(SRCDIR)/mt.c -o $(SRCDIR)/mt.o

test: obj test_common test_primes test_rsa 

test_common:
	$(CC) $(INCLUDES) -g3 -c $(TESTDIR)/common.c -o $(TESTDIR)/common.o
	$(CC) $(INCLUDES) -g3 -c $(TESTDIR)/test.c -o $(TESTDIR)/test.o
	$(CC) $(INCLUDES) -g3 -o $(BUILDDIR)/test_bin $(TESTDIR)/test.o $(TESTDIR)/common.o $(SRCDIR)/rsa.o $(SRCDIR)/mt.o -lz -lcrypto

test_primes:
	$(CC) $(INCLUDES) -g3 -c $(TESTDIR)/primes.c -o $(TESTDIR)/test_primes.o
	$(CC) $(INCLUDES) -g3 -o $(BUILDDIR)/primes_bin $(TESTDIR)/test_primes.o $(SRCDIR)/primes.o $(SRCDIR)/std.o -lcrypto

test_rsa:
	$(CC) $(INCLUDES) -g3 -c $(TESTDIR)/rsa.c -o $(TESTDIR)/test_rsa.o
	$(CC) $(INCLUDES) -g3 -o $(BUILDDIR)/rsa_bin $(TESTDIR)/test_rsa.o $(SRCDIR)/rsa.o -lcrypto

smoke: test
	$(CC) -I$(SRCDIR) -I. -g3 -c $(TESTDIR)/smoke.c -o$(TESTDIR)/smoke.o
	$(CC) -I$(SRCDIR) -I. -o$(BUILDDIR)/smoke_bin $(TESTDIR)/smoke.o $(TESTDIR)/common.o $(SRCDIR)/rsa.o $(SRCDIR)/std.o $(SRCDIR)/primes.o $(SRCDIR)/mt.o -lcrypto -lz

.PHONY: clean

clean:
	rm -rf *.o *_bin
