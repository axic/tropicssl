
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS
# To compile on MinGW: add "-lws2_32" to LDFLAGS

CFLAGS	= -I../include -O
LDFLAGS	= -L../library -lxyssl

APPS =	aes/aescrypt2		hash/hello		\
	hash/md5sum		hash/sha1sum		\
	hash/sha2sum		pkey/dh_client		\
	pkey/dh_genprime	pkey/dh_server		\
	pkey/mpi_demo		pkey/rsa_genkey		\
	pkey/rsa_sign		pkey/rsa_verify		\
	ssl/ssl_client1		ssl/ssl_client2		\
	ssl/ssl_server		test/benchmark		\
	test/selftest

.SILENT:

all: $(APPS)

aes/aescrypt2: aes/aescrypt2.c ../library/libxyssl.a
	echo   "  CC    aes/aescrypt2.c"
	$(CC) $(CFLAGS) aes/aescrypt2.c     $(LDFLAGS) -o $@

hash/hello: hash/hello.c ../library/libxyssl.a
	echo   "  CC    hash/hello.c"
	$(CC) $(CFLAGS) hash/hello.c        $(LDFLAGS) -o $@

hash/md5sum: hash/md5sum.c ../library/libxyssl.a
	echo   "  CC    hash/md5sum.c"
	$(CC) $(CFLAGS) hash/md5sum.c       $(LDFLAGS) -o $@

hash/sha1sum: hash/sha1sum.c ../library/libxyssl.a
	echo   "  CC    hash/sha1sum.c"
	$(CC) $(CFLAGS) hash/sha1sum.c      $(LDFLAGS) -o $@

hash/sha2sum: hash/sha2sum.c ../library/libxyssl.a
	echo   "  CC    hash/sha2sum.c"
	$(CC) $(CFLAGS) hash/sha2sum.c      $(LDFLAGS) -o $@

pkey/dh_client: pkey/dh_client.c ../library/libxyssl.a
	echo   "  CC    pkey/dh_client.c"
	$(CC) $(CFLAGS) pkey/dh_client.c    $(LDFLAGS) -o $@

pkey/dh_genprime: pkey/dh_genprime.c ../library/libxyssl.a
	echo   "  CC    pkey/dh_genprime.c"
	$(CC) $(CFLAGS) pkey/dh_genprime.c  $(LDFLAGS) -o $@

pkey/dh_server: pkey/dh_server.c ../library/libxyssl.a
	echo   "  CC    pkey/dh_server.c"
	$(CC) $(CFLAGS) pkey/dh_server.c    $(LDFLAGS) -o $@

pkey/mpi_demo: pkey/mpi_demo.c ../library/libxyssl.a
	echo   "  CC    pkey/mpi_demo.c"
	$(CC) $(CFLAGS) pkey/mpi_demo.c     $(LDFLAGS) -o $@

pkey/rsa_genkey: pkey/rsa_genkey.c ../library/libxyssl.a
	echo   "  CC    pkey/rsa_genkey.c"
	$(CC) $(CFLAGS) pkey/rsa_genkey.c   $(LDFLAGS) -o $@

pkey/rsa_sign: pkey/rsa_sign.c ../library/libxyssl.a
	echo   "  CC    pkey/rsa_sign.c"
	$(CC) $(CFLAGS) pkey/rsa_sign.c     $(LDFLAGS) -o $@

pkey/rsa_verify: pkey/rsa_verify.c ../library/libxyssl.a
	echo   "  CC    pkey/rsa_verify.c"
	$(CC) $(CFLAGS) pkey/rsa_verify.c   $(LDFLAGS) -o $@

ssl/ssl_client1: ssl/ssl_client1.c ../library/libxyssl.a
	echo   "  CC    ssl/ssl_client1.c"
	$(CC) $(CFLAGS) ssl/ssl_client1.c   $(LDFLAGS) -o $@

ssl/ssl_client2: ssl/ssl_client2.c ../library/libxyssl.a
	echo   "  CC    ssl/ssl_client2.c"
	$(CC) $(CFLAGS) ssl/ssl_client2.c   $(LDFLAGS) -o $@

ssl/ssl_server: ssl/ssl_server.c ../library/libxyssl.a
	echo   "  CC    ssl/ssl_server.c"
	$(CC) $(CFLAGS) ssl/ssl_server.c    $(LDFLAGS) -o $@

test/benchmark: test/benchmark.c ../library/libxyssl.a
	echo   "  CC    test/benchmark.c"
	$(CC) $(CFLAGS) test/benchmark.c    $(LDFLAGS) -o $@

test/selftest: test/selftest.c ../library/libxyssl.a
	echo   "  CC    test/selftest.c"
	$(CC) $(CFLAGS) test/selftest.c     $(LDFLAGS) -o $@

clean:
	rm -f $(APPS)

