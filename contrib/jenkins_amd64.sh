#!/bin/sh
# jenkins build helper script for libosmocore. This is how we build on jenkins.osmocom.org

. $(dirname "$0")/jenkins_common.sh

ENABLE_SANITIZE="--enable-sanitize"

if [ "x$label" = "xFreeBSD_amd64" ]; then
        ENABLE_SANITIZE=""
fi

src_dir="$PWD"
build() {
    build_dir="$1"

    prep_build "$src_dir" "$build_dir"

    "$src_dir"/configure  --disable-silent-rules --enable-static $ENABLE_SANITIZE --enable-werror

    run_make
}

# verify build in dir other than source tree
build builddir
# verify build in source tree
build .

# do distcheck only once, which is fine from built source tree, since distcheck
# is well separated from the source tree state.
$MAKE distcheck \
    || cat-testlogs.sh

osmo-clean-workspace.sh
