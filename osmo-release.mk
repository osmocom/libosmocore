ifdef REL
NEW_VERSION := $(shell bumpversion --list --current-version $(VERSION) $(REL) --allow-dirty | awk -F '=' '{ print $$2 }')
LIBVERS := $(shell git grep -n LIBVERSION | grep  '=' | grep am | grep -v LDFLAGS)
ISODATE := $(shell date -I)
endif

release:
ifeq ($(NEW_VERSION),)
	@$(error Failed to determine NEW_VERSION - please fix versioning (current is $(VERSION)) before proceeding with the release)
endif
	@echo "Releasing" $(VERSION) "->" $(NEW_VERSION)"..."
ifeq ($(LIBVERS),)
	@gbp dch --debian-tag='%(version)s' --auto --meta --git-author --multimaint-merge
else
	@echo "You should NOT be doing this unless you've read and understood following article:"
	@echo "https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html#Updating-version-info"
	@grep -v '#' TODO-RELEASE | sed 's/\t\+/:/g' | xargs -d'\n' -I entry dch -m -v $(NEW_VERSION) "entry"
	@dch -r -m --distribution "unstable" ""
	@grep '#' TODO-RELEASE > TODO-RELEASE.clean
	@mv TODO-RELEASE.clean TODO-RELEASE
	@echo "Do NOT push the release commit if you have not adjusted LIBVERSION in preceeding commit!!!"
	@echo "Are you sure the following versions are correct?"
	@echo $(LIBVERS)
endif
	@git add -u
	@bumpversion --current-version $(VERSION) $(REL) --tag --commit --tag-name $(NEW_VERSION) --allow-dirty
	@git tag -s $(NEW_VERSION) -f -m "Release v$(NEW_VERSION) on $(ISODATE)."
	@echo "Release" $(NEW_VERSION) "prepared, tagged and signed."
