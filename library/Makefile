
# Compilation flags:
#
#    SELF_TEST          enable all checkup routines
#    HAVE_RDTSC         CPU supports rdtsc (x86 only)
#    HAVE_SSE2          CPU supports sse2  (x86 only)
#    HAVE_LONGLONG      compiler supports long long
#    _BSD_EXTENSION     needed to compile on Plan 9
#
# Add -fPIC to CFLAGS to compile as a shared library

DEFINES	= -DSELF_TEST -DHAVE_RDTSC #-DHAVE_SSE2
CFLAGS	= $(DEFINES) -I../include/xyssl -O #-fPIC

OBJS=aes.o       arc4.o      base64.o    bignum.o    \
     certs.o     des.o       dhm.o       havege.o    \
     md2.o       md4.o       md5.o       net.o       \
     rsa.o       sha1.o      sha2.o      ssl_cli.o   \
     ssl_srv.o   ssl_tls.o   timing.o    x509_read.o

all: static

static: libxyssl.a

libxyssl.a: $(OBJS)
	@echo "  AR    $@"; ar r $@ $(OBJS)

shared: libxyssl.so

libxyssl.so: libxyssl.a
	@echo "  LD    $@"; gcc -shared -Wl,-soname,$@ \
	    -o $@ $(OBJS)

.c.o:
	@echo "  CC    $<"; $(CC) $(CFLAGS) -c $<

clean:
	@rm -f *.o libxyssl.*

