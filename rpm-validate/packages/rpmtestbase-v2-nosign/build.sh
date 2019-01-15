#!/bin/bash

rm -rf /root/rpmbuild
mkdir -p /root/rpmbuild/SOURCES
cp rpmtestbase /root/rpmbuild/SOURCES/rpmtestbase
rpmbuild -ba rpmtestbase.spec

cp /root/rpmbuild/RPMS/x86_64/rpmtestbase-2-2.x86_64.rpm .
