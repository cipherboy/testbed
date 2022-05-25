clean:
	rm -f nss-byok

build:
	gcc -Og -ggdb -DDEBUG -Wall -Werror -Wextra -std=c11 main.c pairs.c $(shell pkg-config --cflags --libs nss) -o nss-byok

database:
	rm -rf nssdb && mkdir -p nssdb && certutil -N -d nssdb --empty-password
