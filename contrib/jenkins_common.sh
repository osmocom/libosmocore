#!/bin/sh

set -ex

verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

prep_build() {
    _src_dir="$1"
    _build_dir="$2"

    cd "$_src_dir"

    # a failed 'make distcheck' may leave files without write permissions
    chmod -R a+w .
    git clean -dxf
    # make absolutely sure no src files have modifications
    git checkout -f HEAD

    autoreconf --install --force

    mkdir -p "$_build_dir"
    cd "$_build_dir"
}
