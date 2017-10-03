ifndef REL
	REL := patch
endif

release:
ifeq ($(origin REL), file)
	@echo "No REL value specified, defaulting to 'patch' release"
endif
	@osmo-release.sh $(VERSION) $(REL)
