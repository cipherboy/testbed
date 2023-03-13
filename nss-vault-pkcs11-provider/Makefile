LIBRARY ?= /home/cipherboy/GitHub/hashicorp/vault-pkcs11-provider/libvault-pkcs11.so
NSS_DBG_DIR ?= /home/cipherboy/GitHub/nss-dev
CC ?= clang

clean:
	rm -f nss-validator

build:
	$(CC) -Og -ggdb -DDEBUG -Wall -Werror -Wextra -std=c11 tests.c main.c $(shell pkg-config --cflags --libs nss) -o nss-validator

debug-build:
	$(CC) -Og -ggdb -DDEBUG=1 -DNSS_ALLOWS_MANUAL_EXTRACTION=1 -Wall -Werror -Wextra -std=c11 tests.c main.c -I$(NSS_DBG_DIR)/dist/public/nss -I$(NSS_DBG_DIR)/dist/Debug/include/nspr -L$(NSS_DBG_DIR)/dist/Debug/lib -Wl,-rpath=$(NSS_DBG_DIR)/dist/Debug/lib -Wl,-rpath-link=$(NSS_DBG_DIR)/dist/Debug/lib  -lnss3 -lnssutil3 -lsmime3 -lssl3 -lplds4 -lplc4 -lnspr4 -Wl,-rpath=$(NSS_DBG_DIR)/dist/Debug/lib -Wl,-rpath-link=$(NSS_DBG_DIR)/dist/Debug/lib -DNSS_ALLOWS_MANUAL_EXTRACTION=1 -o nss-validator

debug-asan-build:
	$(CC) -fsanitize=address -Og -ggdb -DDEBUG=1 -DNSS_ALLOWS_MANUAL_EXTRACTION=1 -Wall -Werror -Wextra -std=c11 tests.c main.c -I$(NSS_DBG_DIR)/dist/public/nss -I$(NSS_DBG_DIR)/dist/Debug/include/nspr -L$(NSS_DBG_DIR)/dist/Debug/lib -Wl,-rpath=$(NSS_DBG_DIR)/dist/Debug/lib -Wl,-rpath-link=$(NSS_DBG_DIR)/dist/Debug/lib  -lnss3 -lnssutil3 -lsmime3 -lssl3 -lplds4 -lplc4 -lnspr4 -Wl,-rpath=$(NSS_DBG_DIR)/dist/Debug/lib -Wl,-rpath-link=$(NSS_DBG_DIR)/dist/Debug/lib -DNSS_ALLOWS_MANUAL_EXTRACTION=1 -o nss-validator

database:
	rm -rf nssdb && mkdir -p nssdb && certutil -N -d nssdb --empty-password && modutil -add vault-pkcs11-provider -libfile ${LIBRARY} -dbdir nssdb -force

database-softhsm:
	rm -rf nssdb .softhsm/hsm && mkdir -p nssdb .softhsm/hsm && softhsm2-util --init-token --free --label "wrapper-test" --pin 12345 --so-pin 12345 && certutil -N -d nssdb --empty-password && modutil -add vault-pkcs11-provider -libfile /usr/lib/softhsm/libsofthsm2.so -dbdir nssdb -force
