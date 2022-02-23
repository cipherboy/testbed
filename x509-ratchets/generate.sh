#!/bin/bash

source libs.sh

(
  rm -rf verify_certificate
  go build ./verify_certificate.go
  export PATH="$PWD:$PATH"

  rm -rf experiments ; mkdir -p experiments ; cd experiments

  set -ex

  mkdir -p leaves

  # Generate various certificates.
  genkey old
  initca old root-old

  genkey inter-a
  initsubca inter-a inter-a root-old

  genkey server
  signcsr inter-a server www.example.com leaves/www.example.com.crt

  genkey new
  initca new root-new

  genkey inter-b
  initsubca inter-b inter-b root-new

  signcsr inter-b server email.example.com leaves/email.example.com.crt

  initca old root-old root-old-reissued 010101

  crosssign root-new inter-a
  crosssign root-old root-new
  crosssign root-old inter-b

  # Validate chain constructions against multiple validation implementations.
  shouldvalidate www.example.com leaves/www.example.com.crt inter-a -- root-old
  shouldvalidate www.example.com leaves/www.example.com.crt inter-a -- root-old-reissued
  shouldvalidate www.example.com leaves/www.example.com.crt inter-a -- root-old root-new
  shouldvalidate www.example.com leaves/www.example.com.crt inter-a -- root-old-reissued root-new
  shouldvalidate www.example.com leaves/www.example.com.crt cross-root-new:inter-a -- root-new
  shouldvalidate www.example.com leaves/www.example.com.crt cross-root-new:inter-a -- root-new root-old
  shouldvalidate www.example.com leaves/www.example.com.crt cross-root-new:inter-a -- root-new root-old-reissued
  shouldvalidate www.example.com leaves/www.example.com.crt inter-a cross-root-new:inter-a -- root-new
  shouldvalidate www.example.com leaves/www.example.com.crt cross-root-new:inter-a inter-a -- root-old # OpenSSL requires inter-a to be after cross-root-new:inter-a for verification to succeed
  shouldvalidate www.example.com leaves/www.example.com.crt inter-a cross-root-new:inter-a -- root-new root-old
  shouldvalidate www.example.com leaves/www.example.com.crt inter-a cross-root-new:inter-a -- root-new root-old-reissued
  shouldvalidate www.example.com leaves/www.example.com.crt cross-root-new:inter-a cross-root-old:root-new -- root-old
  shouldvalidate www.example.com leaves/www.example.com.crt cross-root-new:inter-a cross-root-old:root-new -- root-old root-new

  # Validate a reissued root can be validated by itself. However, note that
  # this fails in OpenSSL presently (as the openssl verify appears to use
  # other validation logic than TLS validation does).
  # shouldvalidate root-old ca/root-old-reissued/certs/ca.pem -- root-old
  # shouldvalidate root-old ca/root-old/certs/ca.pem -- root-old-reissued
)
