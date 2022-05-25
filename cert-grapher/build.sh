#!/bin/bash

set -e

mkdir -p graphs/
rm graphs/* || true
go run ./main.go

ls graphs/*.dot | parallel -j0 dot -Tpng {} -o {.}-dot.png
