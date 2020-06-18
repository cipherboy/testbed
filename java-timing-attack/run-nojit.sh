#!/bin/bash

javac Main.java && java -Djava.compiler=NONE -Xint -XX:-UseCompiler Main
