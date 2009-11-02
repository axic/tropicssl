
all:
	make -C NIST nisttest
	make -C DIE.C diehard
	rm -f DIE.C/*.o
	mv -f DIE.C/diehard .

clean:
	rm -f nisttest diehard

