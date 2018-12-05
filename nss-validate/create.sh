#!/bin/bash

set -e

# Set environment variables
SKID="0x`openssl rand -hex 20`"
OCSP="http://ca.cipherboy.com:8080/ca/ocsp"
nssdb="dbs/create"

# Clean up current databases
rm $nssdb -rf noise.bin *.crt *.csr *.der password.txt

# Create empty password for our database
touch password.txt


# Create NSS DB
mkdir -p $nssdb
certutil -N -d $nssdb -f password.txt


## We're going to create six certificates:
##
## A CA Root key -- base CA key, root of trust -- "CA Root"
## A CA Sub key -- signed by the root -- "CA Sub"
## A service key -- signed by the root -- "a.cipherboy.com"
## A second service key -- signed by the sub key -- "b.cipherboy.com"
## A random key -- not signed by the root -- "c.cipherboy.com"
## A second random key -- signed by the first random key -- "d.cipherboy.com"
##
## Of these, only the Root CA is directly trusted.
## The sub-key is trusted by virtue of the Root CA being trusted
## The service keys are trusted because they derive trust through the Root CA
## The random keys are not trusted as they're not connected to the Root.


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


# Create CA Sub

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

echo -e "${SKID}\ny\n2\n7\n\n\n\n" |
 certutil -R \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -k rsa \
 -g 4096 \
 -Z SHA256 \
 -n "CA Sub" \
 -s "CN=CA Sub Certificate,OU=pki-tomcat,O=CIPHERBOY" \
 -o ca_sub.csr.der
openssl req -inform der -in ca_sub.csr.der -out ca_sub.csr

# Sign CA Sub

echo -e "y\n\n\n\n\n\n\n2\n7\n${OCSP}\n\n\n" |
 certutil -C \
 -d $nssdb \
 -f password.txt \
 -m $RANDOM \
 -a \
 -i ca_sub.csr \
 -o ca_sub.crt \
 -c "CA Root" \
 -3 \
 --extAIA \
 --keyUsage critical,certSigning,crlSigning,digitalSignature,nonRepudiation \
 --extAIA \
 --extSKID

# Import CA Sub
certutil -d $nssdb -A -n "CA Sub" -t "CTu,Cu,Cu" -a -i ca_sub.crt


# Create Server Key A (signed by Root)

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

certutil -R \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -k rsa \
 -g 4096 \
 -Z SHA256 \
 -s "CN=a.cipherboy.com,O=CIPHERBOY" \
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
certutil -d $nssdb -A -n a.cipherboy.com -t u,u,u -a -i sslserver-a.crt



# Create Server Key B (signed by Root)

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

certutil -R \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -k rsa \
 -g 4096 \
 -Z SHA256 \
 -s "CN=b.cipherboy.com,O=CIPHERBOY" \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth \
 -o sslserver-b.csr.der
openssl req -inform der -in sslserver-b.csr.der -out sslserver-b.csr

# Sign server key
echo -e "y\n\n\n\n\n2\n7\n${OCSP}\n\n\n" |
 certutil -C \
 -d $nssdb \
 -f password.txt \
 -m $RANDOM \
 -a \
 -i sslserver-b.csr \
 -o sslserver-b.crt \
 -c "CA Sub" \
 -3 \
 --extAIA \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth

# Import server key into NSS DB
certutil -d $nssdb -A -n b.cipherboy.com -t u,u,u -a -i sslserver-b.crt



# Create Server Key C (not signed)

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

echo -e "y\n\n\n\n\n2\n7\n${OCSP}\n\n\n\n" | \
 certutil -S \
 -x \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -n "c.cipherboy.com" \
 -s "CN=b.cipherboy.com,O=CIPHERBOY" \
 -t "u,u,u" \
 -m $RANDOM \
 -k rsa \
 -g 4096 \
 -Z SHA256 \
 -3 \
 --extAIA \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth
certutil -L -d $nssdb -n "c.cipherboy.com" -a > sslserver-c.crt




echo ""
echo ""
echo ""
echo "Listing NSSDB contents"

certutil -L -d $nssdb
certutil -K -d $nssdb
