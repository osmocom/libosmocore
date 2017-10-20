#!/bin/sh
# jenkins build helper script for libosmo-sccp.  This is how we build on jenkins.osmocom.org

. $(dirname "$0")/jenkins_common.sh

ENABLE_SANITIZE="--enable-sanitize"

if [ "x$label" = "xFreeBSD_amd64" ]; then
        ENABLE_SANITIZE=""
fi

build() {
    $1 --enable-static $2 CFLAGS="-Werror" CPPFLAGS="-Werror"
$MAKE $PARALLEL_MAKE check \
  || cat-testlogs.sh
$MAKE distcheck \
  || cat-testlogs.sh
}

# verify build in dir other than source tree
mkdir -p builddir
cd builddir
build ../configure $ENABLE_SANITIZE

cd ..
build ./configure $ENABLE_SANITIZE

