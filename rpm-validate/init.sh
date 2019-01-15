#!/bin/sh

# Rather than doing a minimal cleaning, remove the repository and start fresh
# each time. This doesn't matter as we always put v1 back.
rm -rf /repos/testing
mkdir -p /repos/testing

# Copy the valid gpg key into the repository so we can find it more easily.
cp keys/rpmtestbase-valid-B903B604.gpg /repos/testing/valid.gpg
