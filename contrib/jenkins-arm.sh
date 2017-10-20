#!/bin/sh

. $(dirname "$0")/jenkins_common.sh

build() {
    $1 --enable-static \
	--prefix=/usr/local/arm-none-eabi \
	--host=arm-none-eabi \
	--enable-embedded \
	--disable-doxygen \
	--disable-shared \
	CFLAGS="-Os -ffunction-sections -fdata-sections -nostartfiles -nodefaultlibs -Werror"

$MAKE $PARALLEL_MAKE \
	|| cat-testlogs.sh
}

# verify build in dir other than source tree
mkdir -p builddir
cd builddir
build ../configure

cd ..
build ./configure

