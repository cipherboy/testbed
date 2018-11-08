#!/bin/bash

set -e

# Create NSS DB

rm nssdb -rf noise.bin *.crt *.csr *.der

echo Secret.123 > password.txt
openssl rand -out noise.bin 2048
mkdir nssdb
certutil -N -d nssdb -f password.txt

# Create CA
# https://www.dogtagpki.org/wiki/Creating_Self-Signed_CA_Signing_Certificate_with_NSS

openssl rand -out noise.bin 2048
SKID="0x`openssl rand -hex 20`"
OCSP="http://$HOSTNAME:8080/ca/ocsp"
echo -e "y\n\ny\ny\n${SKID}\n\n\n\n${SKID}\n\n2\n7\n${OCSP}\n\n\n\n" | \
 certutil -S \
 -x \
 -d nssdb \
 -f password.txt \
 -z noise.bin \
 -n "CA Signing Certificate" \
 -s "CN=CA Signing Certificate,OU=pki-tomcat,O=CIPHERBOY" \
 -t "CT,C,C" \
 -m $RANDOM \
 -k rsa \
 -g 2048 \
 -Z SHA256 \
 -2 \
 -3 \
 --keyUsage critical,certSigning,crlSigning,digitalSignature,nonRepudiation \
 --extAIA \
 --extSKID
certutil -L -d nssdb -n "CA Signing Certificate" -a > ca_signing.crt


# Create CSR
# https://www.dogtagpki.org/wiki/Generating_SSL_Server_CSR_with_NSS

certutil -R \
 -d nssdb \
 -f password.txt \
 -z noise.bin \
 -k rsa \
 -g 2048 \
 -Z SHA256 \
 -s "CN=ca,O=CIPHERBOY" \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth \
 -o sslserver.csr.der
openssl req -inform der -in sslserver.csr.der -out sslserver.csr



# Sign CSR
# https://www.dogtagpki.org/wiki/Issuing_SSL_Server_Certificate_with_NSS

echo "$SKID - $OCSP"
echo -e "y\n\ny\ny\n${SKID}\n\n\n\n2\n7\n${OCSP}\n\n\n\n" |
 certutil -C \
 -d nssdb \
 -f password.txt \
 -m $RANDOM \
 -a \
 -i sslserver.csr \
 -o sslserver.crt \
 -c "CA Signing Certificate" \
 -3 \
 --extAIA \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth

