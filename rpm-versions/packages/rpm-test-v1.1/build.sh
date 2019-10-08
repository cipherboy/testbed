#!/bin/bash

rm -rf "$HOME/rpmbuild"
mkdir -p "$HOME/rpmbuild/SOURCES"
cp rpm-test.info "$HOME/rpmbuild/SOURCES/rpm-test.info"
rpmbuild -ba rpm-test.spec
