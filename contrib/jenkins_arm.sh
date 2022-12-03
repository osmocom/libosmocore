#!/bin/sh

. $(dirname "$0")/jenkins_common.sh


# from ../configure.ac
WERROR_FLAGS="-Werror -Wno-error=deprecated -Wno-error=deprecated-declarations -Wno-error=cpp"

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
	--disable-libsctp \
	--disable-libusb \
	--disable-libmnl \
	CFLAGS="-Os -ffunction-sections -fdata-sections -nostartfiles -nodefaultlibs $WERROR_FLAGS"

    $MAKE $PARALLEL_MAKE
}

# verify build in dir other than source tree
build builddir
# verify build in source tree
build .

osmo-clean-workspace.sh
