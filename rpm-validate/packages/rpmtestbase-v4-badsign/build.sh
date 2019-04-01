#!/bin/bash

rm -rf "$HOME/rpmbuild" *.rpm
mkdir -p "$HOME/rpmbuild/SOURCES"
cp rpmtestbase "$HOME/rpmbuild/SOURCES/rpmtestbase"
rpmbuild -ba rpmtestbase.spec

cp "$HOME/rpmbuild/RPMS/x86_64/rpmtestbase-4-4.x86_64.rpm" .
rpmsign --addsign rpmtestbase-4-4.x86_64.rpm --key-id=B903B604 --digest-algo=sha256
rpm -Kvv rpmtestbase-4-4.x86_64.rpm
mv rpmtestbase-4-4.x86_64.rpm orig.rpm

offset=320
oneoffset=$(( offset + 1 ))

dd if=orig.rpm of=00-file-top.rpm bs=1 count=$offset
dd if=orig.rpm of=99-file-rest.rpm bs=1 skip=$oneoffset
dd if=orig.rpm of=98-file-orig.rpm bs=1 skip=$offset count=1

value="$( xxd -p < 98-file-orig.rpm )"
value="0x$value"
echo "$value"
printf "%x" $(( value - 1 )) | xxd -r -p > 98-file-corrupt.rpm

cat 00-file-top.rpm 98-file-corrupt.rpm 99-file-rest.rpm > "corrupt-$offset.rpm"
cp "corrupt-$offset.rpm" rpmtestbase-4-4.x86_64.rpm
