#!/bin/sh

set -ex

verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

autoreconf --install --force
