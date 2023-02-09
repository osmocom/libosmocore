#!/bin/sh
#
# Print a summary of how often each named object appears in a talloc report.
#
# usage:
#    talloc_count.sh my_talloc_report.txt
# or:
#    osmo_interact_vty.py -p 4242 -c 'show talloc-context application full'  |  talloc_count.sh
#
# produces output like:
#         1 struct foo
#         1 struct log_info
#         1 struct log_info_cat
#        21 msgb
#      1391 SCCP-SCOC(N)[N]
#      1402 struct osmo_fsm_inst
#    [...]

f="$1"

tmpdir="$(mktemp -d)"
trap "rm -rf \"$tmpdir\"" EXIT

# without input file, read stdin
if [ "x$f" = "x" ]; then
	f="$tmpdir/input"
	cat > $f
fi

mangled="$tmpdir/mangled"
grep contains "$f" \
	| sed 's/[ \t]*contains.*//' \
	| sed 's/^[ \t]*//' \
	| sed 's/[ \t][ \t]*/ /g' \
	| grep -v '^$' \
	| grep -v '^[0-9]\+$' \
	| sed 's/0x[0-9a-fA-F]\+/N/g' \
	| sed 's/[0-9]\+/N/g' \
	| sort \
	> "$mangled"

count() {
	name="$1"
	nr="$(grep -Fx "$name" "$mangled" | wc -l)"
	printf "%6d $name\\n" $nr
}

{
	cat "$mangled" | uniq | while read type; do
		count "$type"
	done
} | sort -h
