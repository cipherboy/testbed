#!/bin/sh

sh init.sh
cp packages/rpmtestbase-v1-good/rpmtestbase-1-1.x86_64.rpm /repos/testing
cp packages/rpmtestbase-v4-badsign/rpmtestbase-6-6.x86_64.rpm /repos/testing
sh post.sh
