LIBRARY ?= /home/cipherboy/GitHub/hashicorp/vault-pkcs11-provider/libvault-pkcs11.so

clean:
	rm -f nss-validator

build:
	gcc -Og -ggdb -DDEBUG -Wall -Werror -Wextra -std=c11 tests.c main.c $(shell pkg-config --cflags --libs nss) -o nss-validator

debug-build:
	gcc -Og -ggdb -DDEBUG -Wall -Werror -Wextra -std=c11 tests.c main.c -I/home/cipherboy/GitHub/nss-dev/dist/public/nss -I/home/cipherboy/GitHub/nss-dev/dist/Debug/include/nspr -L/home/cipherboy/GitHub/nss-dev/dist/Debug/lib -lnss3 -lnssutil3 -lsmime3 -lssl3 -lplds4 -lplc4 -lnspr4 -o nss-validator

database:
	rm -rf nssdb && mkdir -p nssdb && certutil -N -d nssdb --empty-password && modutil -add vault-pkcs11-provider -libfile ${LIBRARY} -dbdir nssdb -force

database-softhsm:
	rm -rf nssdb .softhsm/hsm && mkdir -p nssdb .softhsm/hsm && softhsm2-util --init-token --free --label "wrapper-test" --pin 12345 --so-pin 12345 && certutil -N -d nssdb --empty-password && modutil -add vault-pkcs11-provider -libfile /usr/lib/softhsm/libsofthsm2.so -dbdir nssdb -force
