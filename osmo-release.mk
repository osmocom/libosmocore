ifndef REL
	REL := patch
endif

BUMPVER := $(shell bumpversion)
NEW_VER := $(shell bumpversion --list --current-version $(VERSION) $(REL) --allow-dirty | awk -F '=' '{ print $$2 }')
LIBVERS := $(shell git grep -n LIBVERSION | grep  '=' | grep am | grep -v LDFLAGS)
MAKEMOD := $(shell git diff -GLIBVERSION --stat | grep Makefile.am)
ISODATE := $(shell date -I)

release:

ifeq ($(BUMPVER),)
	@$(error Unable to find 'bumpversion' command.)
endif

ifeq ($(NEW_VER),)
	@$(error Please fix versioning to match http://semver.org/ spec (current is $(VERSION)) before proceeding.)
endif

ifeq ($(origin REL), file)
	@echo "No REL value specified, defaulting to 'patch' release"
endif

	@echo "Releasing" $(VERSION) "->" $(NEW_VER)"..."

ifeq ($(LIBVERS),)
	@gbp dch --debian-tag='%(version)s' --auto --meta --git-author --multimaint-merge --ignore-branch
else
	@echo "You should NOT be doing this unless you've read and understood following article:"
	@echo "https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html#Updating-version-info"
	@grep -v '#' TODO-RELEASE | sed 's/\t\+/: /g' > TODO-RELEASE.entries
	@grep '#' TODO-RELEASE > TODO-RELEASE.clean
	@mv TODO-RELEASE.clean TODO-RELEASE
ifeq ($(MAKEMOD),)
	@$(if $(shell git status -s -uno TODO-RELEASE),,$(error Before releasing, please modify some of the libversions: $(LIBVERS)))
endif
	@xargs -a TODO-RELEASE.entries -r -d'\n' -I entry dch -m -v $(NEW_VER) "entry"
endif
	@dch -r -m --distribution "unstable" ""
	@git add -u
	@bumpversion --current-version $(VERSION) $(REL) --tag --commit --tag-name $(NEW_VER) --allow-dirty
	@git tag -s $(NEW_VER) -f -m "Release v$(NEW_VER) on $(ISODATE)."
	@echo "Release" $(NEW_VER) "prepared, tagged and signed."
