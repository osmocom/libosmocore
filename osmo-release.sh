#!/bin/sh
VERSION=$1
REL=$2

if [ "z$REL" = "z" ]; then
	echo "No REL value specified, defaulting to 'patch' release"
	REL="patch"
fi

ALLOW_NO_LIBVERSION_CHANGE="${ALLOW_NO_LIBVERSION_CHANGE:-0}"
ALLOW_NO_LIBVERSION_DEB_MATCH="${ALLOW_NO_LIBVERSION_DEB_MATCH:-0}"
ALLOW_NO_LIBVERSION_RPM_MATCH="${ALLOW_NO_LIBVERSION_RPM_MATCH:-0}"
# Test stuff but don't modify stuff:
DRY_RUN="${DRY_RUN:-0}"

libversion_to_lib_major() {
	libversion="$1"
	current="$(echo "$libversion" | cut -d ":" -f 1)"
	#revision="$(echo "$libversion" | cut -d ":" -f 2)"
	age="$(echo "$libversion" | cut -d ":" -f 3)"
	major="$(expr "$current" - "$age")"
	echo "$major"
}

get_configureac_pkg_check_modules_list() {
	if [ -f "${GIT_TOPDIR}/openbsc/configure.ac" ]; then
		configureac_file="openbsc/configure.ac"
	else
		configureac_file="configure.ac"
	fi
	grep -e "PKG_CHECK_MODULES(" "${GIT_TOPDIR}/${configureac_file}" | cut -d "," -f 2 | tr -d ")" | tr -d "[" | tr -d "]" | tr -d " " | sed "s/>=/ /g"
}

# Make sure that depedency requirement versions match in configure.ac vs debian/control.
#eg: "PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 1.1.0)" vs "libosmocore-dev (>= 1.0.0),"
check_configureac_debctrl_deps_match() {
	get_configureac_pkg_check_modules_list | \
	{ return_error=0
	while read -r dep ver; do

		debctrl_match="$(grep -e "${dep}-dev" ${GIT_TOPDIR}/debian/control | grep ">=")"
		debctrl_match_count="$(echo "$debctrl_match" | grep -c ">=")"
		if [ "z$debctrl_match_count" != "z0" ]; then
			#echo "Dependency <$dep, $ver> from configure.ac matched in debian/control! ($debctrl_match_count)"
			if [ "z$debctrl_match_count" != "z1" ]; then
				echo "WARN: configure.ac <$dep, $ver> matches debian/control $debctrl_match_count times, manual check required!"
			else # 1 match:
				parsed_match=$(echo "$debctrl_match" | tr -d "(" | tr -d ")" | tr -d "," | tr -d " " | tr -d "\t" | sed "s/>=/ /g")
				debctrl_dep=$(echo "$parsed_match" | cut -d " " -f 1 | sed "s/-dev//g")
				debctrl_ver=$(echo "$parsed_match" | cut -d " " -f 2)
				if [ "z$dep" != "z$debctrl_dep" ] || [ "z$ver" != "z$debctrl_ver" ]; then
					echo "ERROR: configure.ac <$dep, $ver> does NOT match debian/control <$debctrl_dep, $debctrl_ver>!"
					return_error=1
				#else
				#	echo "OK: configure.ac <$dep, $ver> matches debian/control <$debctrl_dep, $debctrl_ver>"
				fi
			fi
		fi
	done
	if [ $return_error -ne 0 ]; then
		exit 1
	fi
	}

	# catch and forward exit from pipe subshell "while read":
	if [ $? -ne 0 ]; then
		echo "ERROR: exiting due to previous errors"
		exit 1
	fi
	echo "OK: dependency specific versions in configure.ac and debian/control match"
}

# Make sure that depedency requirement versions match in configure.ac vs contrib/*.spec.in.
#eg: "PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 1.1.0)" vs "pkgconfig(libosmocore-dev) >= 1.0.0,"
check_configureac_rpmspecin_deps_match() {
	# Some projects don't have rpm spec files:
	if [ "z$(find "${GIT_TOPDIR}/contrib" -name "*.spec.in" | wc -l)" = "z0" ]; then
		echo "INFO: Project has no 'contrib/*.spec.in' files, skipping RPM specific configure.ac dependency version checks"
		return
	fi

	get_configureac_pkg_check_modules_list | \
	{ return_error=0
	while read -r dep ver; do

		rpmspecin_match="$(grep -e "pkgconfig(${dep})" ${GIT_TOPDIR}/contrib/*.spec.in | grep BuildRequires | grep pkgconfig | grep ">=")"
		rpmspecin_match_count="$(echo "$rpmspecin_match" | grep -c ">=")"
		if [ "z$rpmspecin_match_count" != "z0" ]; then
			#echo "Dependency <$dep, $ver> from configure.ac matched in contrib/*.spec.in! ($rpmspecin_match_count)"
			if [ "z$rpmspecin_match_count" != "z1" ]; then
				echo "WARN: configure.ac <$dep, $ver> matches contrib/*.spec.in $rpmspecin_match_count times, manual check required!"
			else # 1 match:
				parsed_match=$(echo "$rpmspecin_match" | tr -d "(" | tr -d ")" | tr -d ":" | tr -d " " | tr -d "\t" | sed "s/BuildRequires//g" | sed "s/pkgconfig//g" |sed "s/>=/ /g")
				rpmspecin_dep=$(echo "$parsed_match" | cut -d " " -f 1)
				rpmspecin_ver=$(echo "$parsed_match" | cut -d " " -f 2)
				if [ "z$dep" != "z$rpmspecin_dep" ] || [ "z$ver" != "z$rpmspecin_ver" ]; then
					echo "ERROR: configure.ac <$dep, $ver> does NOT match contrib/*.spec.in <$rpmspecin_dep, $rpmspecin_ver>!"
					return_error=1
				#else
				#	echo "OK: configure.ac <$dep, $ver> matches contrib/*.spec.in <$debctrl_dep, $debctrl_ver>"
				fi
			fi
		fi
	done
	if [ $return_error -ne 0 ]; then
		exit 1
	fi
	}

	# catch and forward exit from pipe subshell "while read":
	if [ $? -ne 0 ]; then
		echo "ERROR: exiting due to previous errors"
		exit 1
	fi
	echo "OK: dependency specific versions in configure.ac and contrib/*.spec.in match"
}

# Make sure that patches under debian/patches/ apply:
check_debian_patch_apply() {
	if [ ! -d "${GIT_TOPDIR}/debian/patches" ]; then
		return
	fi
	for patch in ${GIT_TOPDIR}/debian/patches/*.patch; do
		git apply --check $patch
		if [ $? -ne 0 ]; then
			echo "ERROR: patch no longer applies! $patch"
			exit 1
		else
			echo "OK: patch applies: $patch"
		fi
	done
}

libversion_deb_match() {
	echo "$LIBVERS" | while read -r line; do
		libversion=$(echo "$line" | cut -d "=" -f 2 | tr -d "[:space:]")
		major="$(libversion_to_lib_major "$libversion")"
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
}

libversion_rpmspecin_match() {
	# Some projects don't have rpm spec files:
	if [ "z$(find "${GIT_TOPDIR}/contrib" -name "*.spec.in" | wc -l)" = "z0" ]; then
		echo "INFO: Project has no 'contrib/*.spec.in' files, skipping RPM specific LIBVERSION checks"
		return
	fi

	echo "$LIBVERS" | while read -r line; do
		libversion=$(echo "$line" | cut -d "=" -f 2 | tr -d "[:space:]")
		major="$(libversion_to_lib_major "$libversion")"

		control_matches="$(grep -e "%files" "${GIT_TOPDIR}/contrib/"*.spec.in | grep "lib" | grep "$major$" | wc -l)"
		if [ "z$control_matches" = "z0" ]; then
			echo "ERROR: Found no matching '%files -n lib*$major' in contrib/*.spec.in for LIBVERSION=$libversion"
			exit 1
		elif [ "z$control_matches" = "z1" ]; then
			echo "OK: Found '%files -n lib*$major' in contrib/*.spec.in for LIBVERSION=$libversion"
		else
			echo "WARN: Found $file_matches files matching '%files -n lib*$major' in contrib/*.spec.in for LIBVERSION=$libversion, manual check required!"
		fi

		control_matches="$(grep -e "_libdir" "${GIT_TOPDIR}/contrib/"*.spec.in | grep "/lib" | grep "so.$major" | wc -l)"
		if [ "z$control_matches" = "z0" ]; then
			echo "ERROR: Found no matching '%_libdir/lib*.so.$major*' in contrib/*.spec.in for LIBVERSION=$libversion"
			exit 1
		elif [ "z$control_matches" = "z1" ]; then
			echo "OK: Found '%_libdir/lib*.so.$major*' in contrib/*.spec.in for LIBVERSION=$libversion"
		else
			echo "WARN: Found $file_matches files matching '%_libdir/lib*.so.$major*' in contrib/*.spec.in for LIBVERSION=$libversion, manual check required!"
		fi
	done
	# catch and forward exit from pipe subshell "while read":
	if [ $? -ne 0 ]; then
		exit 1
	fi
}


BUMPVER=`command -v bumpversion`
if [ "z$BUMPVER" = "z" ]; then
	echo Unable to find 'bumpversion' command.
	exit 1
fi
NEW_VER=`$BUMPVER --list --current-version $VERSION $REL --allow-dirty | awk -F '=' '{ print $2 }'`
if [ "z$NEW_VER" = "z" ]; then
	echo "Please fix versioning to match http://semver.org/ spec (current is $VERSION) before proceeding."
	exit 1
fi
GIT_TOPDIR="$(git rev-parse --show-toplevel)"
LIBVERS=`git grep -n LIBVERSION | grep  '=' | grep am | grep -v LDFLAGS | grep -v osmo-release.sh`
MAKEMOD=`git diff --cached -GLIBVERSION --stat | grep Makefile.am`
ISODATE=`date -I`

echo "Releasing $VERSION -> $NEW_VER..."

check_configureac_debctrl_deps_match
check_configureac_rpmspecin_deps_match
check_debian_patch_apply

if [ "z$LIBVERS" != "z" ]; then
	if [ "z$MAKEMOD" = "z" ] && [ "z$ALLOW_NO_LIBVERSION_CHANGE" = "z0" ]; then
		echo "ERROR: Before releasing, please modify some of the libversions: $LIBVERS"
		echo "You should NOT be doing this unless you've read and understood following article:"
		echo "https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html#Updating-version-info"
		exit 1
	fi
	if [ "z$ALLOW_NO_LIBVERSION_DEB_MATCH" = "z0" ]; then
		libversion_deb_match
	fi
	if [ "z$ALLOW_NO_LIBVERSION_RPM_MATCH" = "z0" ]; then
		libversion_rpmspecin_match
	fi
fi

if [ "z$DRY_RUN" != "z0" ]; then
	exit 0
fi

set -e
if [ -f "TODO-RELEASE" ]; then
	grep '#' TODO-RELEASE > TODO-RELEASE.clean || true
	mv TODO-RELEASE.clean TODO-RELEASE
	git add TODO-RELEASE
fi

# Add missing epoch (OS#5046)
DEB_VER=$(head -1 debian/changelog | cut -d ' ' -f 2 | sed 's,(,,'  | sed 's,),,')
NEW_VER_WITH_EPOCH="$NEW_VER"
case "$DEB_VER" in
*:*)
	epoch="$(echo "$DEB_VER" | cut -d: -f1)"
	NEW_VER_WITH_EPOCH="$epoch:$NEW_VER"
	;;
esac

gbp dch \
	--debian-tag='%(version)s' \
	--auto \
	--meta \
	--git-author \
	--multimaint-merge \
	--ignore-branch \
	--new-version="$NEW_VER_WITH_EPOCH"
dch -r -m --distribution "unstable" ""
git add ${GIT_TOPDIR}/debian/changelog
$BUMPVER --current-version $VERSION $REL --tag --commit --tag-name $NEW_VER --allow-dirty
git commit --amend # let the user add extra information to the release commit.
git tag -s $NEW_VER -f -m "Release v$NEW_VER on $ISODATE."
echo "Release $NEW_VER prepared, tagged and signed."
