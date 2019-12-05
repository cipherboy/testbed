#!/bin/bash

export nssdb=/nssdb
export SKID="0x`openssl rand -hex 20`"
export OCSP="http://ca.cipherboy.com:8080/ca/ocsp"

export servername="localhost"

certutil -N -d $nssdb -f $nssdb/password.txt

cd $nssdb

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

echo -e "y\n\ny\ny\n${SKID}\n\n\n\n${SKID}\n\n2\n7\n${OCSP}\n\n\n\n" | \
 certutil -S \
 -x \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -n "CA Root" \
 -s "CN=CA Root Certificate,OU=pki-tomcat,O=CIPHERBOY" \
 -t "CTu,Cu,Cu" \
 -m $RANDOM \
 -k rsa \
 -g 4096 \
 -Z SHA256 \
 -2 \
 -3 \
 --keyUsage critical,certSigning,crlSigning,digitalSignature,nonRepudiation \
 --extAIA \
 --extSKID 
certutil -L -d $nssdb -n "CA Root" -a > ca_root.crt

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

certutil -R \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -k rsa \
 -g 4096 \
 -Z SHA256 \
 -s "CN=$servername,O=CIPHERBOY" \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth \
 -o sslserver-a.csr.der
openssl req -inform der -in sslserver-a.csr.der -out sslserver-a.csr

# Sign server key
echo -e "y\n\n\n\n\n2\n7\n${OCSP}\n\n\n" |
 certutil -C \
 -d $nssdb \
 -f password.txt \
 -m $RANDOM \
 -a \
 -i sslserver-a.csr \
 -o sslserver-a.crt \
 -c "CA Root" \
 -3 \
 --extAIA \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth

# Import server key into NSS DB
certutil -d $nssdb -A -n $servername -t u,u,u -a -i sslserver-a.crt -f password.txt
