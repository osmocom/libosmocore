#!/usr/bin/env bash

set -ex

./contrib/verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

autoreconf --install --force
./configure --enable-static --enable-sanitize
$MAKE $PARALLEL_MAKE check \
  || cat-testlogs.sh
$MAKE distcheck \
  || cat-testlogs.sh
