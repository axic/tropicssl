
CFLAGS=-Isrc -O2 -W -Wall -DSELF_TEST
LDFLAGS=-L. -lxyssl
DESTDIR=/usr/local

LIB_OBJ=src/aes.o          src/arc4.o         src/base64.o       \
        src/des.o          src/havege.o       src/md2.o          \
        src/md4.o          src/md5.o          src/mpi.o          \
        src/net.o          src/rsa.o          src/sha1.o         \
        src/sha2.o         src/ssl_v3.o       src/ssl_cli.o      \
        src/ssl_srv.o      src/timing.o       src/x509_in.o

APP_OBJ=app/benchmark.x    app/hello.x        app/filecrypt.x    \
        app/rsa_demo.x     app/selftest.x     app/ssl_client.x   \
        app/ssl_server.x

all: libxyssl.a apps

libxyssl.a: $(LIB_OBJ)
	@echo "  AR      $@"; ar r $@ $(LIB_OBJ); ranlib $@

apps: $(APP_OBJ)

%.o: %.c
	@echo "  CC      $<"; $(CC) $(CFLAGS) -c $< -o $@

%.x: %.o libxyssl.a
	@echo "  LD      $<"; $(CC) $< -o $@ $(LDFLAGS)

install:
	mkdir -p  $(DESTDIR)/{include/xyssl,lib}
	cp src/*.h $(DESTDIR)/include/xyssl
	cp libxyssl.a $(DESTDIR)/lib

install-apps:
	mkdir -p $(DESTDIR)/bin
	cp app/*.x $(DESTDIR)/bin

clean:
	@echo "  RM      libxyssl.a"; rm -f libxyssl.a
	@echo "  RM      src/*.o"; rm -f src/*.o
	@echo "  RM      app/*.x"; rm -f app/*.x

