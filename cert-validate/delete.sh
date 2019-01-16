#!/bin/bash

for arg in "$@"; do
    certutil -D -d sql:dbs/verify -f hsm.pin -n "$arg"
    certutil -D -d sql:dbs/verify -f hsm.pin -h NHSM6000-OCS -n "NHSM6000-OCS:$arg"
done

certutil -L -d sql:dbs/verify
certutil -L -d sql:dbs/verify -f hsm.pin -h NHSM6000-OCS
