
DESTDIR=/usr/local
PREFIX=tropicssl_

.SILENT:

all:
	cd library  && make all && cd ..
	cd programs && make all && cd ..

install:
	mkdir -p $(DESTDIR)/include/tropicssl
	cp -r include/tropicssl $(DESTDIR)/include
	
	mkdir -p $(DESTDIR)/lib
	cp library/libtropicssl.* $(DESTDIR)/lib
	
	mkdir -p $(DESTDIR)/bin
	for p in programs/*/* ; do              \
	    if [ -x $$p ] && [ ! -d $$p ] ;     \
	    then                                \
	        f=$(PREFIX)`basename $$p` ;     \
	        cp $$p $(DESTDIR)/bin/$$f ;     \
	    fi                                  \
	done

clean:
	cd library  && make clean && cd ..
	cd programs && make clean && cd ..

