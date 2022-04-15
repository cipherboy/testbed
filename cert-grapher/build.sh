#!/bin/bash

mkdir -p graphs/
rm graphs/*
go run ./main.go

for file in *.dot; do dot -Tpng "$file" -o "${file/.dot/-dot.png}"; done
