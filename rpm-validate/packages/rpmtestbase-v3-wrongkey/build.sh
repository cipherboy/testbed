#!/bin/bash

rm -rf /root/rpmbuild *.rpm
mkdir -p /root/rpmbuild/SOURCES
cp rpmtestbase /root/rpmbuild/SOURCES/rpmtestbase
rpmbuild -ba rpmtestbase.spec

cp /root/rpmbuild/RPMS/x86_64/rpmtestbase-3-3.x86_64.rpm .
rpmsign --addsign rpmtestbase-3-3.x86_64.rpm --key-id=0D811EFA --digest-algo=sha256
rpm -Kvv rpmtestbase-3-3.x86_64.rpm
