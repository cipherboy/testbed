#!/bin/bash

c_flags="-Og -ggdb"
nspr_flags="$(pkg-config --cflags --libs nspr)"
nss_flags="$(pkg-config --cflags --libs nss)"

gcc_flags="$CFLAGS $c_flags $nspr_flags $nss_flags"

gcc $gcc_flags main.c -o c-prfd $gcc_flags
