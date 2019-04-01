#!/bin/bash

set -e

# Set environment variables
SKID="0x`openssl rand -hex 20`"
OCSP="http://ca.cipherboy.com:8080/ca/ocsp"
nssdb="dbs/create"

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

ca_root="CA Root - A"
ca_sub="CA Sub - A.A"
ca_server="CA Server - A.B"
ca_sub_server_a="CA Server - A.A.A"
ca_sub_server_b="CA Server - A.A.B"

comp_root="Compromised Root - B"
comp_sub="Compromised Sub - B.A"
comp_server="Compromised Server - B.B"
comp_sub_server_a="Compromised Server - B.A.A"
comp_sub_server_b="Compromised Server - B.A.B"

self_signed_server="Self Server - C"

# Create CA Root A
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

# Create CA Sub A.A (signed by Root A)

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
 -n "$ca_sub" \
 -s "CN=CA Sub Certificate,OU=pki-tomcat,O=CIPHERBOY" \
 -o ca_sub.csr.der
openssl req -inform der -in ca_sub.csr.der -out ca_sub.csr

# Sign CA Sub A.A

echo -e "y\n\n\n\n\n\n\n2\n7\n${OCSP}\n\n\n" |
 certutil -C \
 -d $nssdb \
 -f password.txt \
 -m $RANDOM \
 -a \
 -i ca_sub.csr \
 -o ca_sub_a_a.crt \
 -c "$ca_root" \
 -v 1024 \
 -3 \
 --extAIA \
 --keyUsage critical,certSigning,crlSigning,digitalSignature,nonRepudiation \
 --extAIA \
 --extSKID

# Import CA Sub
certutil -d $nssdb -A -n "$ca_sub" -t "CTu,Cu,Cu" -a -i ca_sub_a_a.crt
pk12util -o ca_sub_a_a.p12 -d $nssdb -W "" -K "" -n "$ca_sub"


# Create Server Key A.B (signed by Root A)

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

certutil -R \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -k rsa \
 -g 4096 \
 -Z SHA256 \
 -s "CN=ab.cipherboy.com,O=CIPHERBOY" \
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



# Create Server Key A.A.A (signed by Sub A.A)

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

certutil -R \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -k rsa \
 -g 4096 \
 -Z SHA256 \
 -s "CN=aaa.cipherboy.com,O=CIPHERBOY" \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth \
 -o sslserver-a-a-a.csr.der
openssl req -inform der -in sslserver-a-a-a.csr.der -out sslserver-a-a-a.csr

# Sign server key
echo -e "y\n\n\n\n\n2\n7\n${OCSP}\n\n\n" |
 certutil -C \
 -d $nssdb \
 -f password.txt \
 -m $RANDOM \
 -a \
 -i sslserver-a-a-a.csr \
 -o sslserver-a-a-a.crt \
 -c "$ca_sub" \
 -v 1024 \
 -3 \
 --extAIA \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth

# Import server key into NSS DB
certutil -d $nssdb -A -n "$ca_sub_server_a" -t u,u,u -a -i sslserver-a-a-a.crt
pk12util -o sslserver-a-a-a.p12 -d $nssdb -W "" -K "" -n "$ca_sub_server_a"



# Create Server Key A.A.B (signed by Sub A.A)

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

certutil -R \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -k rsa \
 -g 4096 \
 -Z SHA256 \
 -s "CN=aab.cipherboy.com,O=CIPHERBOY" \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth \
 -o sslserver-a-a-b.csr.der
openssl req -inform der -in sslserver-a-a-b.csr.der -out sslserver-a-a-b.csr

# Sign server key
echo -e "y\n\n\n\n\n2\n7\n${OCSP}\n\n\n" |
 certutil -C \
 -d $nssdb \
 -f password.txt \
 -m $RANDOM \
 -a \
 -i sslserver-a-a-b.csr \
 -o sslserver-a-a-b.crt \
 -c "$ca_sub" \
 -v 1024 \
 -3 \
 --extAIA \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth

# Import server key into NSS DB
certutil -d $nssdb -A -n "$ca_sub_server_b" -t u,u,u -a -i sslserver-a-a-b.crt
pk12util -o sslserver-a-a-b.p12 -d $nssdb -W "" -K "" -n "$ca_sub_server_b"











# Create Compromised Root B
# https://www.dogtagpki.org/wiki/Creating_Self-Signed_CA_Signing_Certificate_with_NSS

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

echo -e "y\n\ny\ny\n${SKID}\n\n\n\n${SKID}\n\n2\n7\n${OCSP}\n\n\n\n" | \
 certutil -S \
 -x \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -n "$comp_root" \
 -s "CN=Compromised Root Certificate,OU=pki-tomcat,O=CIPHERBOY" \
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
certutil -L -d $nssdb -n "$comp_root" -a > comp_root_b.crt
pk12util -o comp_root_b.p12 -d $nssdb -W "" -K "" -n "$comp_root"

# Create Compromised Sub B.A (signed by Compromised Root B)

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
 -n "$comp_sub" \
 -s "CN=Compromised Sub Certificate,OU=pki-tomcat,O=CIPHERBOY" \
 -o comp_sub.csr.der
openssl req -inform der -in comp_sub.csr.der -out comp_sub.csr

# Sign Compromised Sub B.A

echo -e "y\n\n\n\n\n\n\n2\n7\n${OCSP}\n\n\n" |
 certutil -C \
 -d $nssdb \
 -f password.txt \
 -m $RANDOM \
 -a \
 -i comp_sub.csr \
 -o comp_sub_b_a.crt \
 -c "$comp_root" \
 -v 1024 \
 -3 \
 --extAIA \
 --keyUsage critical,certSigning,crlSigning,digitalSignature,nonRepudiation \
 --extAIA \
 --extSKID

# Import Compromised Sub
certutil -d $nssdb -A -n "$comp_sub" -t "CTu,Cu,Cu" -a -i comp_sub_b_a.crt
pk12util -o comp_sub_b_a.p12 -d $nssdb -W "" -K "" -n "$comp_sub"


# Create Compromised Server Key B.B (signed by Compromised Root B)

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

certutil -R \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -k rsa \
 -g 4096 \
 -Z SHA256 \
 -s "CN=bb.cipherboy.com,O=CIPHERBOY" \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth \
 -o sslserver-b-b.csr.der
openssl req -inform der -in sslserver-b-b.csr.der -out sslserver-b-b.csr

# Sign server key
echo -e "y\n\n\n\n\n2\n7\n${OCSP}\n\n\n" |
 certutil -C \
 -d $nssdb \
 -f password.txt \
 -m $RANDOM \
 -a \
 -i sslserver-b-b.csr \
 -o sslserver-b-b.crt \
 -c "$comp_root" \
 -v 1024 \
 -3 \
 --extAIA \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth

# Import server key into NSS DB
certutil -d $nssdb -A -n "$comp_server" -t u,u,u -a -i sslserver-b-b.crt
pk12util -o sslserver-b-b.p12 -d $nssdb -W "" -K "" -n "$comp_server"



# Create Compromised Server Key B.A.A (signed by Compromised Sub B.A)

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

certutil -R \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -k rsa \
 -g 4096 \
 -Z SHA256 \
 -s "CN=bab.cipherboy.com,O=CIPHERBOY" \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth \
 -o sslserver-b-a-a.csr.der
openssl req -inform der -in sslserver-b-a-a.csr.der -out sslserver-b-a-a.csr

# Sign server key
echo -e "y\n\n\n\n\n2\n7\n${OCSP}\n\n\n" |
 certutil -C \
 -d $nssdb \
 -f password.txt \
 -m $RANDOM \
 -a \
 -i sslserver-b-a-a.csr \
 -o sslserver-b-a-a.crt \
 -c "$comp_sub" \
 -v 1024 \
 -3 \
 --extAIA \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth

# Import server key into NSS DB
certutil -d $nssdb -A -n "$comp_sub_server_a" -t u,u,u -a -i sslserver-b-a-a.crt
pk12util -o sslserver-b-a-a.p12 -d $nssdb -W "" -K "" -n "$comp_sub_server_a"



# Create Compromised Server Key A.A.B (signed by Compromised Sub A.A)

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

certutil -R \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -k rsa \
 -g 4096 \
 -Z SHA256 \
 -s "CN=bab.cipherboy.com,O=CIPHERBOY" \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth \
 -o sslserver-b-a-b.csr.der
openssl req -inform der -in sslserver-b-a-b.csr.der -out sslserver-b-a-b.csr

# Sign server key
echo -e "y\n\n\n\n\n2\n7\n${OCSP}\n\n\n" |
 certutil -C \
 -d $nssdb \
 -f password.txt \
 -m $RANDOM \
 -a \
 -i sslserver-b-a-b.csr \
 -o sslserver-b-a-b.crt \
 -c "$comp_sub" \
 -v 1024 \
 -3 \
 --extAIA \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth

# Import server key into NSS DB
certutil -d $nssdb -A -n "$comp_sub_server_b" -t u,u,u -a -i sslserver-b-a-b.crt
pk12util -o sslserver-b-a-b.p12 -d $nssdb -W "" -K "" -n "$comp_sub_server_b"























# Create Server Key C (self-signed)

# Generate noise for faster certificate generation
openssl rand -out noise.bin 4096

echo -e "y\n\n\n\n\n2\n7\n${OCSP}\n\n\n\n" | \
 certutil -S \
 -x \
 -d $nssdb \
 -f password.txt \
 -z noise.bin \
 -n "c.cipherboy.com" \
 -s "CN=c.cipherboy.com,O=CIPHERBOY" \
 -t "u,u,u" \
 -m $RANDOM \
 -k rsa \
 -g 4096 \
 -v 1024 \
 -Z SHA256 \
 -3 \
 --extAIA \
 --keyUsage critical,dataEncipherment,keyEncipherment,digitalSignature \
 --extKeyUsage serverAuth
certutil -L -d $nssdb -n "c.cipherboy.com" -a > sslserver-c.crt
pk12util -o sslserver-c.p12 -d $nssdb -W "" -K "" -n "c.cipherboy.com"





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
