
DEFINES=-DSELF_TEST -DHAVE_RDTSC #-DHAVE_SSE2
CFLAGS=-Isrc -O2 -W -Wall $(DEFINES)
LDFLAGS=-L. -lxyssl
DESTDIR=/usr/local

LIB_OBJ=src/aes.o          src/arc4.o         src/base64.o       \
        src/bignum.o       src/des.o          src/dhm.o          \
        src/havege.o       src/md2.o          src/md4.o          \
        src/md5.o          src/net.o          src/rsa.o          \
        src/sha1.o         src/sha2.o         src/ssl_v3.o       \
        src/ssl_cli.o      src/ssl_srv.o      src/testcert.o     \
        src/timing.o       src/x509_in.o

APP_OBJ=app/benchmark      app/hello          app/filecrypt      \
        app/rsa_demo       app/selftest       app/ssl_client     \
        app/ssl_server

all: libxyssl.a apps

libxyssl.a: $(LIB_OBJ)
	@echo "  AR      $@"; ar r $@ $(LIB_OBJ); ranlib $@

%.o: %.c
	@echo "  CC      $<"; $(CC) $(CFLAGS) -c $< -o $@

apps: $(APP_OBJ)

app/%:  app/%.c  libxyssl.a
	@echo "  CC      $<"; $(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

docs:
	@rm -rf doc
	@cd src && doxygen ; cd ..
	@mv html doc

install:
	mkdir -p $(DESTDIR)/{include/xyssl,lib}
	cp src/*.h $(DESTDIR)/include/xyssl
	cp libxyssl.a $(DESTDIR)/lib

install-apps:
	mkdir -p $(DESTDIR)/bin
	for i in $(APP_OBJ); do         \
	    cp $i $(DESTDIR)/xyssl_$i;  \
	done

clean:
	@rm -f libxyssl.a src/*.o app/*.o $(APP_OBJ)

