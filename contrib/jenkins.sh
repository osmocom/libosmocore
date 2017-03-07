#!/usr/bin/env bash

set -ex

./contrib/verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

autoreconf --install --force
./configure --enable-static --enable-sanitize
$MAKE $PARALLEL_MAKE check \
  || cat-testlogs.sh
$MAKE distcheck \
  || cat-testlogs.sh

# verify build in dir other than source tree
rm -rf *
git checkout .
autoreconf --install --force
mkdir builddir
cd builddir
../configure --enable-static
$MAKE $PARALLEL_MAKE check \
  || cat-testlogs.sh
$MAKE distcheck \
  || cat-testlogs.sh
