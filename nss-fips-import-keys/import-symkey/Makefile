CC?=gcc
FLAGS=-I/usr/include/nss3 -I/usr/include/nspr4 -lssl3 -lsmime3 -lnss3 -lnssutil3 -lplds4 -lplc4 -lnspr4 -lpthread -ldl

all: clean a.out check

a.out: main.c
	${CC} ${FLAGS} -o a.out main.c ${FLAGS}

clean:
	rm -rf a.out nssdb

check:
	fips-mode-setup --check
	mkdir -p nssdb
	echo "" > nssdb/password.txt
	certutil -N -d sql:nssdb -f nssdb/password.txt
	./a.out ./nssdb
