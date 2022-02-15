#!/bin/bash

genkey() {(
  local name="$1"
  mkdir -p keys/

  if [ -z "$name" ]; then
    echo "Usage: genkey NAME"
    return 1 >/dev/null 2>&1
    exit 1
  fi

  set -e
  openssl genrsa -out "keys/$name.priv" 2048
  openssl rsa -in "keys/$name.priv" -pubout -out "keys/$name.pub"
)}

ca() {(
  local ca="$1"
  shift

  if [ -z "$ca" ]; then
    echo "Usage: ca CA-NAME [...args...]"
    return 1 >/dev/null 2>&1
    exit 1
  fi

  set -e
  openssl ca -batch -config "ca/$ca/config" "$@"
)}

req() {(
  local ca="$1"
  shift

  if [ -z "$ca" ]; then
    echo "Usage: req CA-NAME [...args...]"
    return 1 >/dev/null 2>&1
    exit 1
  fi

  set -e
  openssl req -config "ca/$ca/config" "$@"
)}

initca() {(
  local key="$1"
  local name="$2"

  if [ -z "$key" ] || [ -z "$name" ]; then
    echo "Usage: initca KEY-NAME CA-NAME"
    return 1 >/dev/null 2>&1
    exit 1
  fi

  mkdir -p "ca/$name"/{certs,reqs,private}
  set -e

  # Setup flat db, copy existing private key
  touch "ca/$name/index.txt"
  cp "keys/$key.priv" "ca/$name/private/private.pem"
  echo "01" > "ca/$name/serial"

  # From https://jamielinux.com/docs/openssl-certificate-authority/appendix/root-configuration-file.html
  # and https://www.phildev.net/ssl/creating_ca.html
  cat > "ca/$name/config" <<_EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = $PWD/ca/$name
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/certs
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand

# The root key and root certificate.
private_key       = \$dir/private/private.pem
certificate       = \$dir/certs/ca.pem

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional

[ req ]
# Options for the openssl req tool (man req).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

[ req_distinguished_name ]
commonName = $name

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = CA:true
subjectAltName=email:move


[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
_EOF

  req "$name" -new -key "ca/$name/private/private.pem" -out "ca/$name/reqs/ca.csr" -subj "/CN=$name"
  ca "$name" -out "ca/$name/certs/ca.pem" -selfsign -extensions v3_ca -subj "/CN=$name" -infiles "ca/$name/reqs/ca.csr"
)}

initsubca() {(
  local key="$1"
  local name="$2"
  local parent="$3"

  if [ -z "$key" ] || [ -z "$name" ] || [ -z "$parent" ]; then
    echo "Usage: initsubca KEY-NAME SUBCA-NAME PARENT-NAME"
    return 1 >/dev/null 2>&1
    exit 1
  fi

  mkdir -p "ca/$name"/{certs,reqs,private}
  set -e

  # Setup flat db, copy existing private key.
  touch "ca/$name/index.txt"
  cp "keys/$key.priv" "ca/$name/private/private.pem"

  # When issuing a subca, let's make the serial numbers unique.
  serial="$(cat "ca/$parent/serial")"
  echo "${serial}01" > "ca/$name/serial"

  # From https://jamielinux.com/docs/openssl-certificate-authority/appendix/root-configuration-file.html
  # and https://www.phildev.net/ssl/creating_ca.html
  cat > "ca/$name/config" <<_EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = $PWD/ca/$name
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/certs
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand

# The root key and root certificate.
private_key       = \$dir/private/private.pem
certificate       = \$dir/certs/ca.pem

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional

[ req ]
# Options for the openssl req tool (man req).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

[ req_distinguished_name ]
commonName = $name

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = CA:true
subjectAltName=email:move


[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
_EOF

  req "$parent" -new -key "ca/$name/private/private.pem" -out "ca/$name/reqs/ca.csr" -subj "/CN=$name"
  cp "ca/$name/reqs/ca.csr" "ca/$parent/reqs/subca-$serial.csr"

  ca "$parent" -out "ca/$parent/certs/subca-$serial.pem" -extensions v3_ca -subj "/CN=$name" -infiles "ca/$parent/reqs/subca-$serial.csr"
  cp "ca/$parent/certs/subca-$serial.pem" "ca/$name/certs/ca.pem"
)}

signcsr() {(
  local ca="$1"
  local key="$2"
  local cn="$3"
  local copy="$4"

  if [ -z "$ca" ] || [ -z "$key" ] || [ -z "$cn" ]; then
    echo "Usage: signcsr CA-NAME KEY-NAME COMMON-NAME [COPY]"
    return 1 >/dev/null 2>&1
    exit 1
  fi

  set -e

  serial="$(cat "ca/$ca/serial")"
  req "$ca" -new -key "keys/$key.priv" -out "ca/$ca/reqs/$serial.csr" -subj "/CN=$cn"
  ca "$ca" -extensions server_cert -subj "/CN=$cn" -infiles "ca/$ca/reqs/$serial.csr"

  if [ -n "$copy" ]; then
    cat "ca/$ca/certs/$serial.pem" > "$copy"
  fi
)}

crosssign() {(
  local parent="$1"
  local name="$2"

  if [ -z "$parent" ] || [ -z "$name" ]; then
    echo "Usage: crosssign PARENT-NAME CHILD-NAME"
    return 1 >/dev/null 2>&1
    exit 1
  fi

  set -e

  serial="$(cat "ca/$parent/serial")"
  req "$parent" -new -key "ca/$name/private/private.pem" -out "ca/$parent/reqs/cross-$serial.csr" -subj "/CN=$name"
  cp "ca/$parent/reqs/cross-$serial.csr" "ca/$name/reqs/cross-$parent.csr"
  ca "$parent" -extensions v3_ca -subj "/CN=$name" -out "ca/$parent/certs/cross-$serial.pem" -infiles "ca/$parent/reqs/cross-$serial.csr"
  cp "ca/$parent/certs/cross-$serial.pem" "ca/$name/certs/cross-$parent.pem"
)}

testsetup() {(
  if [ ! -e tests ]; then
    mkdir -p tests/1
    echo "tests/1"
  else
    for i in `seq 2 10000`; do
      if [ ! -d "tests/$i" ]; then
        mkdir -p "tests/$i"
        echo "tests/$i"
        break
      fi
    done
  fi
)}

shouldvalidate() {(
  local name="$1"
  local leaf="$2"
  shift; shift

  # Remaining arguments are split into two halves:
  local found_split=false
  local root_certs=()
  local chain_certs=("$leaf")

  while (( $# > 0 )); do
    local arg="$1"
    shift

    if [ "$arg" == "--" ]; then
      found_split=true
    else
      if [ "$found_split" == "true" ]; then
        root_certs+=("$arg")
      else
        chain_certs+=("$arg")
      fi
    fi
  done

  if [ -z "$name" ] || [ -z "$leaf" ] || (( ${#root_certs[@]} == 0 )) || (( ${#chain_certs[@]} == 0 )); then
    echo "Roots: [${root_certs[@]}]"
    echo "Chain: [${chain_certs[@]}]"
    echo "Usage: shouldvalidate NAME LEAF [ ... CHAIN ] -- ROOT [ ROOT ... ]"
    return 1 >/dev/null 2>&1
    exit 1
  fi

  set -e

  local dir="$(testsetup)"
  local out_chain="$dir/chain.pem"
  truncate -s 0 "$out_chain"
  local out_trust="$dir/trust.pem"
  truncate -s 0 "$out_trust"

  # Build a chain file.
  for cert in "${chain_certs[@]}"; do
    if [[ $cert = cross-* ]]; then
      local cross_name="${cert//:*/}"
      local ca_name="${cert//*:/}"
      if [ ! -e "ca/$ca_name/certs/$cross_name.pem" ]; then
        echo "Cert not found: $cert ; as $ca_name and $cross_name" 1>&2
        return 1 >/dev/null 2>&1
        exit 1
      fi

      openssl x509 -in "ca/$ca_name/certs/$cross_name.pem" >> "$out_chain"
    elif [ -e "$cert" ]; then
      openssl x509 -in "$cert" >> "$out_chain"
    elif [ -e "ca/$cert/certs/ca.pem" ]; then
      openssl x509 -in "ca/$cert/certs/ca.pem" >> "$out_chain"
    else
      echo "Cert not found: $cert" 1>&2
      return 1 >/dev/null 2>&1
      exit 1
    fi
  done

  for cert in "${root_certs[@]}"; do
    if [ -e "$cert" ]; then
      openssl x509 -in "$cert" >> "$out_trust"
    elif [ -e "ca/$cert/certs/ca.pem" ]; then
      openssl x509 -in "ca/$cert/certs/ca.pem" >> "$out_trust"
    else
      echo "Cert not found: $cert" 1>&2
      return 1 >/dev/null 2>&1
      exit 1
    fi
  done

  validate_openssl "$name" "$out_chain" "$out_trust"
)}

validate_openssl() {(
  local name="$1"
  local chain="$2"
  local root="$3"

  set -e

  # OpenSSL requires certs to be in inverted order from TLS server order. :|
  python3 -c 'import sys; certs=[]; cert=""
for line in sys.stdin:
    cert += line
    if "END CERTIFICATE" in line:
        certs.append(cert)
        cert=""

for cert in reversed(certs):
    print(cert, end="")' < "$chain" > "$chain.openssl"

  openssl verify -verbose -CAfile "$root" -issuer_checks -check_ss_sig -purpose sslserver -x509_strict -policy_print "$chain.openssl"
)}
