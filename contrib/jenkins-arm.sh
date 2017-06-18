#!/bin/sh

set -ex

./contrib/verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

autoreconf --install --force
./configure --enable-static \
	--prefix=/usr/local/arm-none-eabi \
	--host=arm-none-eabi \
	--enable-embedded \
	--disable-shared \
	CFLAGS="-Os -ffunction-sections -fdata-sections -nostartfiles -nodefaultlibs -Werror"

$MAKE $PARALLEL_MAKE \
	|| cat-testlogs.sh

# verify build in dir other than source tree
rm -rf *
git checkout .
autoreconf --install --force
mkdir builddir
cd builddir

../configure --enable-static \
	--prefix=/usr/local/arm-none-eabi \
	--host=arm-none-eabi \
	--enable-embedded \
	--disable-shared \
	CFLAGS="-Os -ffunction-sections -fdata-sections -nostartfiles -nodefaultlibs -Werror"

$MAKE $PARALLEL_MAKE \
	|| cat-testlogs.sh
