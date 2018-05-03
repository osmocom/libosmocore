#!/bin/sh
VERSION=$1
REL=$2

if [ "z$REL" = "z" ]; then
	echo "No REL value specified, defaulting to 'patch' release"
	REL=patch
fi

BUMPVER=`command -v bumpversion`

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
	if [ "z$MAKEMOD" = "z" ]; then
		echo "Before releasing, please modify some of the libversions: $LIBVERS"
		echo "You should NOT be doing this unless you've read and understood following article:"
		echo "https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html#Updating-version-info"
		exit 1
	fi
	if [ -f "TODO-RELEASE" ]; then
		grep '#' TODO-RELEASE > TODO-RELEASE.clean
		mv TODO-RELEASE.clean TODO-RELEASE
		git add TODO-RELEASE
	fi
fi
gbp dch --debian-tag='%(version)s' --auto --meta --git-author --multimaint-merge --ignore-branch --new-version="$NEW_VER"
dch -r -m --distribution "unstable" ""
git add debian/changelog
bumpversion --current-version $VERSION $REL --tag --commit --tag-name $NEW_VER --allow-dirty
git commit --amend # let the user add extra information to the release commit.
git tag -s $NEW_VER -f -m "Release v$NEW_VER on $ISODATE."
echo "Release $NEW_VER prepared, tagged and signed."
