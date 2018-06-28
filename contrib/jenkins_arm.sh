#!/bin/sh

. $(dirname "$0")/jenkins_common.sh

src_dir="$PWD"
build() {
    build_dir="$1"

    prep_build "$src_dir" "$build_dir"

    "$src_dir"/configure --enable-static \
	--prefix=/usr/local/arm-none-eabi \
	--host=arm-none-eabi \
	--enable-embedded \
	--disable-doxygen \
	--disable-shared \
	CFLAGS="-Os -ffunction-sections -fdata-sections -nostartfiles -nodefaultlibs -Werror"

    $MAKE $PARALLEL_MAKE
}

# verify build in dir other than source tree
build builddir
# verify build in source tree
build .

osmo-clean-workspace.sh
