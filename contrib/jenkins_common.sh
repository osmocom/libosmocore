#!/bin/sh

set -ex

if [ -z "$MAKE" ]; then
    set +x
    echo "Error: you need to set \$MAKE before invoking, e.g. MAKE=make"
    exit 1
fi

osmo-clean-workspace.sh

verify_value_string_arrays_are_terminated.py

# Validate enum fields in header are added to tlv_definition in source file (SYS#5891):

verify_gsm0808_tlv_definition() {
    set +x;
    enums=$(grep "GSM0808_IE_" include/osmocom/gsm/protocol/gsm_08_08.h | grep "=" | awk '{ print $1 }')
    counted_enums=$(for f in $enums; do printf "%-60s %s\n" "$f" "$(grep -c "\[$f\]" src/gsm/gsm0808.c)"; done)
    missing_enums=$(echo "$counted_enums" | grep -v GSM0808_IE_RESERVED | grep "0$" || true)
    if [ "x$missing_enums" != "x" ]; then
        echo "Missing IEs in src/gsm/gsm0808.c!"
        echo "$missing_enums"
        exit 1
    fi
    set -x;
}
verify_gsm0808_tlv_definition

verify_gsm_08_05_tlv_definition() {
    set +x;
    enums=$(grep "RSL_IE_" include/osmocom/gsm/protocol/gsm_08_58.h | grep -e "=" -e ",$" | awk '{ print $1 }' | tr -d ',')
    counted_enums=$(for f in $enums; do printf "%-60s %s\n" "$f" "$(grep -c "\[$f\]" src/gsm/rsl.c)"; done)
    # TODO: Add RSL_IE_SIEMENS_* to the tlv struct definitions.
    missing_enums=$(echo "$counted_enums" | grep -v RSL_IE_SIEMENS |grep "0$" || true)
    if [ "x$missing_enums" != "x" ]; then
        echo "Missing IEs in src/gsm/rsl.c!"
        echo "$missing_enums"
        exit 1
    fi
    set -x;
}
verify_gsm_08_05_tlv_definition

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
