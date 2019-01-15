#!/bin/bash

rm -rf /root/rpmbuild *.rpm
mkdir -p /root/rpmbuild/SOURCES
cp rpmtestbase /root/rpmbuild/SOURCES/rpmtestbase
rpmbuild -ba rpmtestbase.spec

cp /root/rpmbuild/RPMS/x86_64/rpmtestbase-5-5.x86_64.rpm .
rpmsign --addsign rpmtestbase-5-5.x86_64.rpm --key-id=B903B604 --digest-algo=sha256
rpm -Kvv rpmtestbase-5-5.x86_64.rpm
