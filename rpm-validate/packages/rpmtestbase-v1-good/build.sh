#!/bin/bash

rm -rf /root/rpmbuild
mkdir -p /root/rpmbuild/SOURCES
cp rpmtestbase /root/rpmbuild/SOURCES/rpmtestbase
rpmbuild -ba rpmtestbase.spec

cp /root/rpmbuild/RPMS/x86_64/rpmtestbase-1-1.x86_64.rpm .
rpmsign --addsign rpmtestbase-1-1.x86_64.rpm --key-id=B903B604 --digest-algo=sha256
rpm -Kvv rpmtestbase-1-1.x86_64.rpm
