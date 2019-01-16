#!/bin/bash

nssdb="dbs/verify"

echo "Making new NSS DB..."

hsm=""
if [ "x$HSM" != "x" ]; then
    hsm="-h '$HSM'"
fi

password=""
if [ "x$PASSWORD" != "x" ]; then
    password="-f '$PASSWORD'"
fi

rm -rf $nssdb
mkdir -p $nssdb
certutil -N -d $nssdb -f password.txt

echo ""
echo ""

for arg in "$@"; do
    if [ "x$arg" == "xroot" ]; then
        echo "Adding root -- trusted!"
        certutil -A -d $nssdb -n "CA Root$SUFFIX" -t "CT,CT,CT" -a -i ca_root.crt
        echo "Result of addition: $?"

        # We assume the root is trusted; so don't validate it using
        # PKICertImport.bash.
    elif [ "x$arg" == "xsub" ]; then
        echo "Adding sub..."
        VERBOSE=1 ./PKICertImport.bash $hsm $password -d $nssdb -n "CA Sub$SUFFIX" -t "CT,C,C" -a -i ca_sub.crt -u "L"
        echo "Result of import: $?"
    elif [ "x$arg" == "xcsub" ]; then
        echo "Adding sub..."
        VERBOSE=1 ./PKICertImport.bash $hsm $password -d $nssdb -n "Compromised Sub$SUFFIX" -t "CT,C,C" -a -i compromised_sub.crt -u "L"
        echo "Result of import: $?"
    elif [ "x$arg" == "xa" ] || [ "x$arg" == "xb" ] || [ "x$arg" == "xc" ] ||
         [ "x$arg" == "xd" ] || [ "x$arg" == "xe" ] ; then
        echo "Adding sslserver-$arg"
        VERBOSE=1 ./PKICertImport.bash $hsm $password -d $nssdb -n "$arg.cipherboy.com$SUFFIX" -t "u,u,u" -a -i "sslserver-${arg}.crt" -u "V"
        echo "Result of import: $?"
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
