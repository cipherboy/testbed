#!/bin/bash

source libs.sh

(
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

  initca old root-old-reissued

  crosssign root-new inter-a
  crosssign root-old root-new
  crosssign root-old inter-b

  # Validate chain constructions against multiple validation implementations.
  shouldvalidate www.example.com leaves/www.example.com.crt inter-a -- root-old
  shouldvalidate www.example.com leaves/www.example.com.crt inter-a -- root-old root-new
  shouldvalidate www.example.com leaves/www.example.com.crt cross-root-new:inter-a -- root-new
  shouldvalidate www.example.com leaves/www.example.com.crt cross-root-new:inter-a -- root-new root-old
  shouldvalidate www.example.com leaves/www.example.com.crt inter-a cross-root-new:inter-a -- root-new
  shouldvalidate www.example.com leaves/www.example.com.crt cross-root-new:inter-a inter-a -- root-old # OpenSSL requires inter-a to be after cross-root-new:inter-a for verification to succeed
  shouldvalidate www.example.com leaves/www.example.com.crt inter-a cross-root-new:inter-a -- root-new root-old
  shouldvalidate www.example.com leaves/www.example.com.crt cross-root-new:inter-a cross-root-old:root-new -- root-old
  shouldvalidate www.example.com leaves/www.example.com.crt cross-root-new:inter-a cross-root-old:root-new -- root-old root-new
)
