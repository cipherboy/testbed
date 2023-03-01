LIBRARY ?= /home/cipherboy/GitHub/hashicorp/vault-pkcs11-provider/libvault-pkcs11.so
CC ?= gcc

clean:
	rm -f nss-validator

build:
	$(CC) -Og -ggdb -DDEBUG -Wall -Werror -Wextra -std=c11 tests.c main.c $(shell pkg-config --cflags --libs nss) -o nss-validator

debug-build:
	$(CC) -Og -ggdb -DDEBUG=1 -DNSS_ALLOWS_MANUAL_EXTRACTION=1 -Wall -Werror -Wextra -std=c11 tests.c main.c -I/home/cipherboy/GitHub/nss-dev/dist/public/nss -I/home/cipherboy/GitHub/nss-dev/dist/Debug/include/nspr -L/home/cipherboy/GitHub/nss-dev/dist/Debug/lib -Wl,-rpath=/home/cipherboy/GitHub/nss-dev/dist/Debug/lib -Wl,-rpath-link=/home/cipherboy/GitHub/nss-dev/dist/Debug/lib  -lnss3 -lnssutil3 -lsmime3 -lssl3 -lplds4 -lplc4 -lnspr4 -Wl,-rpath=/home/cipherboy/GitHub/nss-dev/dist/Debug/lib -Wl,-rpath-link=/home/cipherboy/GitHub/nss-dev/dist/Debug/lib -DNSS_ALLOWS_MANUAL_EXTRACTION=1 -o nss-validator

database:
	rm -rf nssdb && mkdir -p nssdb && certutil -N -d nssdb --empty-password && modutil -add vault-pkcs11-provider -libfile ${LIBRARY} -dbdir nssdb -force

database-softhsm:
	rm -rf nssdb .softhsm/hsm && mkdir -p nssdb .softhsm/hsm && softhsm2-util --init-token --free --label "wrapper-test" --pin 12345 --so-pin 12345 && certutil -N -d nssdb --empty-password && modutil -add vault-pkcs11-provider -libfile /usr/lib/softhsm/libsofthsm2.so -dbdir nssdb -force
