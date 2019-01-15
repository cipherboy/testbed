#!/bin/sh

sh init.sh
cp packages/rpmtestbase-v1-good/rpmtestbase-1-1.x86_64.rpm /repos/testing
cp packages/rpmtestbase-v2-nosign/rpmtestbase-2-2.x86_64.rpm /repos/testing
sh post.sh
