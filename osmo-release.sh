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
MAKEMOD=`git diff -GLIBVERSION --stat | grep Makefile.am`
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

if [ "z$LIBVERS" = "z" ]; then
	gbp dch --debian-tag='%(version)s' --auto --meta --git-author --multimaint-merge --ignore-branch --new-version="$NEW_VER"
else
	echo "You should NOT be doing this unless you've read and understood following article:"
	echo "https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html#Updating-version-info"
	grep -v '#' TODO-RELEASE | sed 's/\t\+/: /g' > TODO-RELEASE.entries
	if [ "$(wc -l <TODO-RELEASE.entries 2>/dev/null)" -eq "0" ]; then
		rm TODO-RELEASE.entries
		echo "TODO-RELEASE must contain at least one line with change descriptions"
		exit 1
	fi
	grep '#' TODO-RELEASE > TODO-RELEASE.clean
	mv TODO-RELEASE.clean TODO-RELEASE
	if [ "z$MAKEMOD" = "z" ]; then
		git status -s -uno TODO-RELEASE
		if [ $? -ne 0 ]; then
			echo "Before releasing, please modify some of the libversions: $LIBVERS"
			exit 1
		fi
	fi
	xargs -a TODO-RELEASE.entries -r -d'\n' -I entry dch -m -v $NEW_VER "entry"
	rm TODO-RELEASE.entries
fi
dch -r -m --distribution "unstable" ""
git add -u
bumpversion --current-version $VERSION $REL --tag --commit --tag-name $NEW_VER --allow-dirty
git tag -s $NEW_VER -f -m "Release v$NEW_VER on $ISODATE."
echo "Release $NEW_VER prepared, tagged and signed."
