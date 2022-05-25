clean:
	rm -f nss-byok

build:
	gcc -Wall -Werror -Wextra -std=c11 main.c pairs.c $(shell pkg-config --cflags --libs nss) -o nss-byok
