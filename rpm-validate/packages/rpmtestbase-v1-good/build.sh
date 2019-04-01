#!/bin/bash

rm -rf "$HOME/rpmbuild"
mkdir -p "$HOME/rpmbuild/SOURCES"
cp rpmtestbase "$HOME/rpmbuild/SOURCES/rpmtestbase"
rpmbuild -ba rpmtestbase.spec

cp "$HOME/rpmbuild/RPMS/x86_64/rpmtestbase-1-1.x86_64.rpm" .
rpmsign --addsign rpmtestbase-1-1.x86_64.rpm --key-id=B903B604 --digest-algo=sha256
rpm -Kvv rpmtestbase-1-1.x86_64.rpm
