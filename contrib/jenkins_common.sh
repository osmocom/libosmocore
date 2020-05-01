#!/bin/sh

set -ex

if [ -z "$MAKE" ]; then
    set +x
    echo "Error: you need to set \$MAKE before invoking, e.g. MAKE=make"
    exit 1
fi

osmo-clean-workspace.sh

verify_value_string_arrays_are_terminated.py

prep_build() {
    _src_dir="$1"
    _build_dir="$2"

    cd "$_src_dir"

    # clean again before each build variant
    osmo-clean-workspace.sh

    autoreconf --install --force

    mkdir -p "$_build_dir"
    cd "$_build_dir"
}

run_make() {
    $MAKE $PARALLEL_MAKE check || cat-testlogs.sh
}
