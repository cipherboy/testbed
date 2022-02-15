#!/bin/bash

source libs.sh

(
  rm -rf experiments ; mkdir -p experiments ; cd experiments

  set -x

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
)
