#!/bin/sh
osmo_auc_gen="$1"

if [ -z "$osmo_auc_gen" ]; then
	echo 'Error: pass a path to the osmo-auc-gen binary as argument:'
	echo '       ./osmo-auc-gen_test.sh /path/to/osmo-auc-gen'
	exit 1
fi

set -e

# run the osmo-auc-gen binary verbosely without showing its absolute path
# for identical expected output everywhere.
invoke() {
	echo
	echo
	echo '>' osmo-auc-gen $@
	$osmo_auc_gen $@
}

invoke_err() {
	echo
	echo
	echo expecting error:
	echo '>' osmo-auc-gen $@
	echo expecting error: >&2
	echo '>' osmo-auc-gen $@ >&2
	$osmo_auc_gen $@ && exit 1 || true
}

bytes1="6a61050765caa32c90371370e5d6dc2d"
bytes2="1dc4f974325cce611e54f516dc1fec56"
bytes3="2a48162ff3edca4adf0b7b5e527d6c16"

invoke -3 -a milenage -r $bytes1 -k $bytes2 -o $bytes3 -s 0
invoke -3 -a milenage -r $bytes1 -k $bytes2 -o $bytes3 -s 1
invoke -3 -a milenage -r $bytes1 -k $bytes2 -o $bytes3 -s 23
invoke -3 -a milenage -r $bytes2 -k $bytes3 -o $bytes1 -s 42
invoke -3 -a milenage -r $bytes3 -k $bytes1 -o $bytes2 -s 99
invoke -3 -a milenage -r $bytes1 -k $bytes3 -o $bytes2 -s 281474976710655

k="EB215756028D60E3275E613320AEC880"
opc="FB2A3D1B360F599ABAB99DB8669F8308"
rand="39fa2f4e3d523d8619a73b4f65c3e14d"
auts="979498b1f72d3e28c59fa2e72f9c" # --> SQN.MS = 23
invoke -3 -a milenage -r $rand -k $k -o $opc -A $auts
invoke -3 -a milenage -r $rand -k $k -o $opc -A $auts --ind 5
invoke -3 -a milenage -r $rand -k $k -o $opc -A $auts --ind 23
invoke -3 -a milenage -r $rand -k $k -o $opc -A $auts --ind 31

invoke -3 -a milenage -r $rand -k $k -o $opc -A $auts --ind-len 0
invoke -3 -a milenage -r $rand -k $k -o $opc -A $auts --ind-len 1
invoke -3 -a milenage -r $rand -k $k -o $opc -A $auts --ind-len 1 --ind 1
invoke -3 -a milenage -r $rand -k $k -o $opc -A $auts --ind-len 8
invoke -3 -a milenage -r $rand -k $k -o $opc -A $auts --ind-len 8 --ind 1

# expect error: IND is too large for IND-bitlen of 5 (max 31)
invoke_err -3 -a milenage -r $rand -k $k -o $opc -A $auts --ind -1
invoke_err -3 -a milenage -r $rand -k $k -o $opc -A $auts --ind 32
invoke_err -3 -a milenage -r $rand -k $k -o $opc -A $auts --ind 42

invoke_err -3 -a milenage -r $rand -k $k -o $opc -A $auts --ind-len 0 --ind 1
