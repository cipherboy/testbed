#!/bin/bash

set -e

# Set environment variables
SKID="0x`openssl rand -hex 20`"
OCSP="http://ca.cipherboy.com:8080/ca/ocsp"
nssdb="nssdb/"

# Clean up current databases
rm $nssdb -rf noise.bin *.crt *.csr *.der password.txt *.p12

# Create empty password for our database
touch password.txt

# Create NSS DB
mkdir -p $nssdb
certutil -N -d $nssdb -f password.txt


## We're going to create six certificates:
##
## A CA Root key -- base CA key, root of trust -- "$ca_root"
## A CA Sub key -- signed by the root -- "$ca_sub"
## A service key -- signed by the root -- "$ca_server"
## A second service key -- signed by the sub key -- "b.cipherboy.com"
## A random key -- not signed by the root -- "c.cipherboy.com"
## A Compromised Root CA -- not trusted -- "Compromised Root"
## A Compromised Sub CA -- signed by Compromised Root -- "Compromised Sub"
## A fourth service key -- signed by Compromised Root -- "d.hacked.com"
## A fifth service key -- signed by Compromised Sub -- "e.hacked.com"
##
## Of these, only the Root CA is directly trusted.
## The sub-key is trusted by virtue of the Root CA being trusted
## The service keys are trusted because they derive trust through the Root CA
## The random keys are not trusted as they're not connected to the Root.

ca_root="rootca"
ca_server="sslserver"

# Create CA Root
# https://www.dogtagpki.org/wiki/Creating_Self-Signed_CA_Signing_Certificate_with_NSS

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

echo -e "y\n\ny\ny\n${SKID}\n\n\n\n${SKID}\n\n2\n7\n${OCSP}\n\n\n\n" | \
 certutil -S \
 -x \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -n "$ca_root" \
 -s "CN=CA Root Certificate,OU=pki-tomcat,O=CIPHERBOY" \
 -t "CTu,Cu,Cu" \
 -m $RANDOM \
 -k rsa \
 -g 4096 \
 -v 1024 \
 -Z SHA256 \
 -2 \
 -3 \
 --keyUsage critical,certSigning,crlSigning,digitalSignature,nonRepudiation \
 --extAIA \
 --extSKID
certutil -L -d $nssdb -n "$ca_root" -a > ca_root_a.crt
pk12util -o ca_root_a.p12 -d $nssdb -W "" -K "" -n "$ca_root"

# Create Server key (Signed by the Root CA)

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

certutil -R \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -k rsa \
 -g 4096 \
 -Z SHA256 \
 -s "CN=localhost,O=CIPHERBOY" \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth \
 -o sslserver-a-b.csr.der
openssl req -inform der -in sslserver-a-b.csr.der -out sslserver-a-b.csr

# Sign server key
echo -e "y\n\n\n\n\n2\n7\n${OCSP}\n\n\n" |
 certutil -C \
 -d $nssdb \
 -f password.txt \
 -m $RANDOM \
 -a \
 -i sslserver-a-b.csr \
 -o sslserver-a-b.crt \
 -c "$ca_root" \
 -v 1024 \
 -3 \
 --extAIA \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth

# Import server key into NSS DB
certutil -d $nssdb -A -n "$ca_server" -t u,u,u -a -i sslserver-a-b.crt
pk12util -o sslserver-a-b.p12 -d $nssdb -W "" -K "" -n "$ca_server"

echo ""
echo ""
echo ""
echo "Listing NSSDB contents"

certutil -L -d $nssdb
certutil -K -d $nssdb

cat sslserver-a.crt > joint-a.crt
cat ca_sub.crt sslserver-b.crt > joint-b.crt
cat sslserver-c.crt > joint-c.crt
cat sslserver-d.crt > joint-d.crt
cat compromised_sub.crt sslserver-e.crt > joint-e.crt
