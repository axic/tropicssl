
CFLAGS=/O2 /W3 /MT /nologo /Fo$@ /DWIN32 /DSELF_TEST #\DHAVE_SSE2
LDFLAGS=xyssl.lib kernel32.lib shell32.lib user32.lib

LIB_OBJ=library\aes.obj           library\arc4.obj          \
        library\base64.obj        library\bignum.obj        \
        library\certs.obj         library\des.obj           \
        library\dhm.obj           library\havege.obj        \
        library\md2.obj           library\md4.obj           \
        library\md5.obj           library\net.obj           \
        library\rsa.obj           library\sha1.obj          \
        library\sha2.obj          library\sha4.obj          \
        library\ssl_cli.obj       library\ssl_srv.obj       \
        library\ssl_tls.obj       library\timing.obj        \
        library\x509read.obj

PRG_OBJ=programs\aes\aescrypt2.exe      \
        programs\hash\hello.exe         \
        programs\hash\md5sum.exe        \
        programs\hash\sha1sum.exe       \
        programs\hash\sha2sum.exe       \
        programs\pkey\dh_client.exe     \
        programs\pkey\dh_genprime.exe   \
        programs\pkey\dh_server.exe     \
        programs\pkey\mpi_demo.exe      \
        programs\pkey\rsa_genkey.exe    \
        programs\pkey\rsa_sign.exe      \
        programs\pkey\rsa_verify.exe    \
        programs\ssl\ssl_client1.exe    \
        programs\ssl\ssl_client2.exe    \
        programs\ssl\ssl_server.exe     \
        programs\test\benchmark.exe     \
        programs\test\selftest.exe

default: lib prg

lib:  $(LIB_OBJ) ; @echo.
	@lib /out:xyssl.lib $(LIB_OBJ)
	@del library\*.obj

prg:  $(PRG_OBJ) ; @echo.

.c.obj: ; @$(CC) $(CFLAGS) /I"include" /c $<

.c.exe: ; @$(CC) $(CFLAGS) /I"include" $(LDFLAGS) $<
	@del $@
