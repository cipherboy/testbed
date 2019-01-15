#!/bin/sh

sh init.sh
cp packages/rpmtestbase-v1-good/rpmtestbase-1-1.x86_64.rpm /repos/testing
cp packages/rpmtestbase-v3-wrongkey/rpmtestbase-3-3.x86_64.rpm /repos/testing
sh post.sh
