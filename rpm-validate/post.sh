#!/bin/sh

# Add our repository information to yum so it can find it.
cp repos-testing.repo /etc/yum.repos.d/repos-testing.repo

# createrepo will build a valid RPM repository for use with yum from whatever
# RPM files are placed in that folder.
cd /repos/testing
createrepo .

# Clean caches. Sometimes this is necessary if things have changed, e.g.,
# gpgcheck, etc.
yum clean all
