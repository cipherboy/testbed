#!/bin/bash

nssdb="dbs/verify"

echo "Making new NSS DB..."

rm -rf $nssdb
mkdir -p $nssdb
certutil -N -d $nssdb -f password.txt

echo ""
echo ""

for arg in "$@"; do
    if [ "x$arg" == "xroot" ]; then
        echo "Adding root -- trusted!"
        certutil -A -d $nssdb -n "CA Root" -t "CT,CT,CT" -a -i ca_root.crt
        echo "Result of addition: $?"

        # We assume the root is trusted; so don't validate it.
    elif [ "x$arg" == "xsub" ]; then
        echo "Adding sub"
        certutil -A -d $nssdb -n "CA Sub" -t "w,w,w" -a -i ca_sub.crt
        echo "Result of addition: $?"
        echo ""
        echo "Verifying sub:"
        certutil -V -d $nssdb -n "CA Sub" -u "C"
        ret=$?
        echo "Result of verification: $ret"
        if [ "$ret" == "0" ]; then
            echo ""
            echo "Upgrading trust to trusted"
            certutil -M -d $nssdb -n "CA Sub" -t "CT,CT,CT"
            echo "Result of upgrading: $?"
        fi
    elif [ "x$arg" == "xa" ] || [ "x$arg" == "xb" ] || [ "x$arg" == "xc" ]; then
        echo "Adding sslserver-$arg"
        certutil -A -d "$nssdb" -n "$arg.cipherboy.com" -t "w,w,w" -a -i "sslserver-${arg}.crt"
        echo "Result of addition: $?"
        echo ""
        echo "Verifying sslserver-$arg"
        certutil -V -d $nssdb -n "$arg.cipherboy.com" -u "V"
        ret=$?
        echo "Result of verification: $ret"
        if [ "$ret" == "0" ]; then
            echo ""
            echo "Upgrading trust to trusted"
            certutil -M -d $nssdb -n "$arg.cipherboy.com" -t "u,u,u"
            echo "Result of upgrading: $?"
        fi
    fi
    echo ""
    echo ""
done

echo ""
echo ""
echo ""
echo "Listing NSSDB contents"

certutil -L -d $nssdb || true
certutil -K -d $nssdb || true

