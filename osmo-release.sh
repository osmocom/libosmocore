#!/bin/sh
VERSION=$1
REL=$2

if [ "z$REL" = "z" ]; then
	echo "No REL value specified, defaulting to 'patch' release"
	REL="patch"
fi

ALLOW_NO_LIBVERSION_CHANGE="${ALLOW_NO_LIBVERSION_CHANGE:-0}"
ALLOW_NO_LIBVERSION_DEB_MATCH="${ALLOW_NO_LIBVERSION_DEB_MATCH:-0}"
# Test stuff but don't modify stuff:
DRY_RUN="${DRY_RUN:-0}"

libversion_to_deb_major() {
	libversion="$1"
	current="$(echo "$libversion" | cut -d ":" -f 1)"
	#revision="$(echo "$libversion" | cut -d ":" -f 2)"
	age="$(echo "$libversion" | cut -d ":" -f 3)"
	major="$(expr "$current" - "$age")"
	echo "$major"
}

BUMPVER=`command -v bumpversion`
GIT_TOPDIR="$(git rev-parse --show-toplevel)"
NEW_VER=`bumpversion --list --current-version $VERSION $REL --allow-dirty | awk -F '=' '{ print $2 }'`
LIBVERS=`git grep -n LIBVERSION | grep  '=' | grep am | grep -v LDFLAGS`
MAKEMOD=`git diff --cached -GLIBVERSION --stat | grep Makefile.am`
ISODATE=`date -I`

if [ "z$BUMPVER" = "z" ]; then
	echo Unable to find 'bumpversion' command.
	exit 1
fi

if [ "z$NEW_VER" = "z" ]; then
	echo "Please fix versioning to match http://semver.org/ spec (current is $VERSION) before proceeding."
	exit 1
fi

echo "Releasing $VERSION -> $NEW_VER..."

if [ "z$LIBVERS" != "z" ]; then
	if [ "z$MAKEMOD" = "z" ] && [ "z$ALLOW_NO_LIBVERSION_CHANGE" = "z0" ]; then
		echo "ERROR: Before releasing, please modify some of the libversions: $LIBVERS"
		echo "You should NOT be doing this unless you've read and understood following article:"
		echo "https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html#Updating-version-info"
		exit 1
	fi
	if [ "z$ALLOW_NO_LIBVERSION_DEB_MATCH" = "z0" ]; then
		echo "$LIBVERS" | while read -r line; do
			libversion=$(echo "$line" | cut -d "=" -f 2 | tr -d "[:space:]")
			major="$(libversion_to_deb_major "$libversion")"
			file_matches="$(find "${GIT_TOPDIR}/debian" -name "lib*${major}.install" | wc -l)"
			if [ "z$file_matches" = "z0" ]; then
				echo "ERROR: Found no matching debian/lib*$major.install file for LIBVERSION=$libversion"
				exit 1
			elif [ "z$file_matches" = "z1" ]; then
				echo "OK: Found matching debian/lib*$major.install for LIBVERSION=$libversion"
			else
				echo "WARN: Found $file_matches files matching debian/lib*$major.install for LIBVERSION=$libversion, manual check required!"
			fi

			control_matches="$(grep -e "Package" "${GIT_TOPDIR}/debian/control" | grep "lib" | grep "$major$" | wc -l)"
			if [ "z$control_matches" = "z0" ]; then
				echo "ERROR: Found no matching Package lib*$major in debian/control for LIBVERSION=$libversion"
				exit 1
			elif [ "z$control_matches" = "z1" ]; then
				echo "OK: Found 'Package: lib*$major' in debian/control for LIBVERSION=$libversion"
			else
				echo "WARN: Found $file_matches files matching 'Package: lib*$major' in debian/control for LIBVERSION=$libversion, manual check required!"
			fi

			dhstrip_lib_total="$(grep -e "dh_strip" "${GIT_TOPDIR}/debian/rules" | grep "\-plib" | wc -l)"
			dhstrip_lib_matches="$(grep -e "dh_strip" "${GIT_TOPDIR}/debian/rules" | grep "\-plib" | grep "$major" | wc -l)"
			if [ "z$dhstrip_lib_total" != "z0" ]; then
				if [ "z$dhstrip_lib_matches" = "z0" ] ; then
					echo "ERROR: Found no matching 'dh_strip -plib*$major' line in debian/rules for LIBVERSION=$libversion"
					exit 1
				elif [ "z$dhstrip_lib_total" = "z1" ]; then
					echo "OK: Found 'dh_strip -plib*$major' in debian/rules for LIBVERSION=$libversion"
				else
					echo "WARN: Found $dhstrip_lib_matches/$dhstrip_lib_total dh_strip matches 'dh_strip -plib*$major' in debian/rules for LIBVERSION=$libversion, manual check required!"
				fi
			fi
		done
		# catch and forward exit from pipe subshell "while read":
		if [ $? -ne 0 ]; then
			exit 1
		fi
	fi
	if [ "z$DRY_RUN" != "z0" ]; then
		exit 0
	fi
	if [ -f "TODO-RELEASE" ]; then
		grep '#' TODO-RELEASE > TODO-RELEASE.clean
		mv TODO-RELEASE.clean TODO-RELEASE
		git add TODO-RELEASE
	fi
fi

if [ "z$DRY_RUN" != "z0" ]; then
	exit 0
fi
gbp dch --debian-tag='%(version)s' --auto --meta --git-author --multimaint-merge --ignore-branch --new-version="$NEW_VER"
dch -r -m --distribution "unstable" ""
git add debian/changelog
bumpversion --current-version $VERSION $REL --tag --commit --tag-name $NEW_VER --allow-dirty
git commit --amend # let the user add extra information to the release commit.
git tag -s $NEW_VER -f -m "Release v$NEW_VER on $ISODATE."
echo "Release $NEW_VER prepared, tagged and signed."
