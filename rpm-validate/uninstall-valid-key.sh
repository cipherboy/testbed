#!/bin/sh

# This removes the valid gpg key. The hex characters align with the full
# 64-bit key identifier for the master key. This procedure is documented
# in the following mailing list post:
#
# https://www.redhat.com/archives/rpm-list/2005-March/msg00050.html

rpm -e --allmatches gpg-pubkey-b903b604-5c19386e
