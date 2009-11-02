
DESTDIR=/usr/local

.SILENT:

all:
	cd library  && make all && cd ..
	cd programs && make all && cd ..

install:
	mkdir -p $(DESTDIR)/{include/xyssl,lib}
	cp -v -r include $(DESTDIR)/include
	cp -v library/libxyssl.a $(DESTDIR)/lib
	
	mkdir -p $(DESTDIR)/bin
	for p in programs/*/* ; do              \
	    if [ -x $$p ] ; then                \
                f=bin/xyssl_`basename $$p` ;    \
	        cp -v $$p  $(DESTDIR)/$$f  ;    \
	    fi                                  \
	done

clean:
	cd library  && make clean && cd ..
	cd programs && make clean && cd ..

