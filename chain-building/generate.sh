#!/bin/bash

source libs.sh

(
  rm -rf experiments ; mkdir -p experiments ; cd experiments

  set -ex

  mkdir -p leaves

  # Generate root and intermediate certificates.
  genkey key-root-old
  initca key-root-old root-old
  initca key-root-old root-old root-old-reissued 1337

  genkey key-inter-old-a
  initsubca key-inter-old-a inter-old-a root-old

  genkey key-inter-old-b
  initsubca key-inter-old-b inter-old-b root-old

  genkey key-root-new
  initca key-root-new root-new
  initca key-root-new root-alt

  genkey key-inter-new
  initsubca key-inter-new inter-new root-new

  genkey key-inter-alt
  initsubca key-inter-alt inter-alt root-alt

  # Generate some cross-signed intermediate CAs
  genkey key-cross-old-new
  initsubca key-cross-old-new cross-old-new root-new
  crosssign root-old cross-old-new

  genkey key-cross-old-new-alt
  initsubca key-cross-old-new-alt cross-old-new-alt root-alt
  crosssign root-old cross-old-new-alt
  crosssign root-new cross-old-new-alt

  # Create some SubCAs off of intermediates.
  genkey key-inter-cross-old-new
  initsubca key-inter-cross-old-new inter-cross-old-new cross-old-new

  genkey key-inter-cross-old-new-alt
  initsubca key-inter-cross-old-new-alt inter-cross-old-new-alt cross-old-new-alt

  # Bootstrap a circular CA (why not?!)
  genkey key-circle-a
  genkey key-circle-b
  initca key-circle-a cirtcle-a circle-a-bootstrap
  initsubca key-circle-b circle-b circle-a-bootstrap
  initsubca key-circle-a circle-a circle-b
)
