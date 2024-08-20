#!/bin/bash

create_repo() {(
	rm -rf repos/ repos.bak/

	mkdir -p repos/example
	cd repos/example
	git init .

	git status
	echo "initial" > README.md
	git add README.md && git commit -m "initial"

	git status
	echo "lib symlink" > README.md
	mkdir lib64
	echo "whoami" > lib64/code.sh
	ln -s lib64 lib
	git add lib64 lib README.md && git commit -m "lib symlink"

	git status
	echo "absolute symlink" > README.md
	ln -s /bin/bash lib64/shell
	git add lib64/shell README.md && git commit -m "absolute symlink"

	git status
	echo "latest change" > README.md
	git add README.md && git commit -m "latest change"

	git log | cat -
)}

backup_repo() {(
	cp -pr repos/ repos.bak
)}

create_repo
backup_repo

go mod tidy
# go run ./main.go

(
	cd repos/example && go run ../../main.go .
)
