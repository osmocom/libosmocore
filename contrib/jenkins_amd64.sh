#!/bin/sh
# jenkins build helper script for libosmocore. This is how we build on jenkins.osmocom.org

. $(dirname "$0")/jenkins_common.sh

src_dir="$PWD"
build() {
    build_dir="$1"

    prep_build "$src_dir" "$build_dir"

    "$src_dir"/configure  --disable-silent-rules --enable-static --enable-sanitize --enable-werror \
        --enable-external-tests

    run_make
}

# verify build in dir other than source tree
build builddir
# verify build in source tree
build .

# do distcheck only once, which is fine from built source tree, since distcheck
# is well separated from the source tree state.
DISTCHECK_CONFIGURE_FLAGS=--enable-external-tests \
    $MAKE $PARALLEL_MAKE distcheck \
    || cat-testlogs.sh
$MAKE maintainer-clean

osmo-clean-workspace.sh
