#!/bin/bash

mkdir -p graphs/
rm graphs/*
go run ./main.go

ls graphs/*.dot | parallel -j0 dot -Tpng {} -o {.}-dot.png
