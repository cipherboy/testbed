#!/bin/bash

nssdb="dbs/verify"
type="sql"

echo "Making new NSS DB..."

hsm=""
if [ "x$HSM" != "x" ]; then
    hsm="-h $HSM"
fi

password=""
if [ "x$PASSWORD" != "x" ]; then
    password="-f $PASSWORD"
fi

rm -rf $nssdb
mkdir -p $nssdb
certutil -N -d "$type:$nssdb" -f password.txt
if [ "x$HSM" != "x" ]; then
    modutil -dbdir "$type:$nssdb" -nocertdb -add nfast -libfile /opt/nfast/toolkits/pkcs11/libcknfast.so
fi


echo ""
echo ""

for arg in "$@"; do
    if [ "x$arg" == "xroot" ]; then
        echo "Adding root -- trusted!"
        certutil -A $hsm $password -d "$type:$nssdb" -n "CA Root$SUFFIX" -t "CT,CT,CT" -a -i ca_root.crt
        echo "Result of addition: $?"

        # We assume the root is trusted; so don't validate it using
        # PKICertImport.bash.
    elif [ "x$arg" == "xsub" ]; then
        echo "Adding sub..."
        VERBOSE=1 ./PKICertImport.bash $hsm $password -d $nssdb -n "CA Sub$SUFFIX" -t "CT,C,C" -i ca_sub.p12 -u "L" -p -w password.txt
        echo "Result of import: $?"
    elif [ "x$arg" == "xcsub" ]; then
        echo "Adding sub..."
        VERBOSE=1 ./PKICertImport.bash $hsm $password -d $nssdb -n "Compromised Sub$SUFFIX" -t "CT,C,C" -i compromised_sub.p12 -u "L" -p -w password.txt
        echo "Result of import: $?"
    elif [ "x$arg" == "xa" ] || [ "x$arg" == "xb" ] || [ "x$arg" == "xc" ] ||
         [ "x$arg" == "xd" ] || [ "x$arg" == "xe" ] ; then
        echo "Adding sslserver-$arg"
        VERBOSE=1 ./PKICertImport.bash $hsm $password -d $nssdb -n "$arg.cipherboy.com$SUFFIX" -t "u,u,u" -i "sslserver-${arg}.p12" -u "V" -p -w password.txt
        echo "Result of import: $?"
    fi
    echo ""
    echo ""
done

echo ""
echo ""
echo ""
echo "Listing NSSDB contents"

certutil -L -d "$type:$nssdb" || true
certutil -K -d "$type:$nssdb" || true
certutil -L -d "$type:$nssdb" $hsm $password || true
certutil -K -d "$type:$nssdb" $hsm $password || true
