
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS
# To compile on MingW: add "-lws2_32" to LDFLAGS

CFLAGS	= -I../include -O
LDFLAGS	= -L../library -lxyssl

APPS=benchmark hello filecrypt mpi_demo selftest \
     ssl_client1 ssl_client2 ssl_server

.SILENT:

all: $(APPS)

benchmark:  benchmark.c ../library/libxyssl.a
	echo   "  CC    benchmark.c"
	$(CC) $(CFLAGS) benchmark.c  $(LDFLAGS) -o benchmark

hello:      hello.c     ../library/libxyssl.a
	echo   "  CC    hello.c"
	$(CC) $(CFLAGS) hello.c      $(LDFLAGS) -o hello

filecrypt:  filecrypt.c ../library/libxyssl.a
	echo   "  CC    filecrypt.c"
	$(CC) $(CFLAGS) filecrypt.c  $(LDFLAGS) -o filecrypt

mpi_demo:   mpi_demo.c  ../library/libxyssl.a
	echo   "  CC    mpi_demo.c"
	$(CC) $(CFLAGS) mpi_demo.c   $(LDFLAGS) -o mpi_demo

selftest:   selftest.c  ../library/libxyssl.a
	echo   "  CC    selftest.c"
	$(CC) $(CFLAGS) selftest.c   $(LDFLAGS) -o selftest

ssl_client1:  ssl_client1.c ../library/libxyssl.a
	echo   "  CC    ssl_client1.c"
	$(CC) $(CFLAGS) ssl_client1.c $(LDFLAGS) -o ssl_client1

ssl_client2:  ssl_client2.c ../library/libxyssl.a
	echo   "  CC    ssl_client2.c"
	$(CC) $(CFLAGS) ssl_client2.c $(LDFLAGS) -o ssl_client2

ssl_server: ssl_server.c ../library/libxyssl.a
	echo   "  CC    ssl_server.c"
	$(CC) $(CFLAGS) ssl_server.c $(LDFLAGS) -o ssl_server

clean:
	rm -f $(APPS)

