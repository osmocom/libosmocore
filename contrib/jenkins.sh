#!/usr/bin/env bash

set -ex

./contrib/verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

if [ "x$label" = "xFreeBSD_amd64" ]; then
        ENABLE_SANITIZE=""
else
        ENABLE_SANITIZE="--enable-sanitize"
fi

autoreconf --install --force
./configure --enable-static $ENABLE_SANITIZE
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
