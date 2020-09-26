.PHONY: clean-local install-data-hook uninstall-local

EXTRA_DIST = libosmocore.stp
TAPSET_FILES = $(EXTRA_DIST)
TAPSET_INSTALL_DIR = $(DESTDIR)@ABS_TAPSET_DIR@

if ENABLE_SYSTEMTAP
all-local: $(TAPSET_FILES)

clean-local:

install-data-hook:
	$(MKDIR_P) $(TAPSET_INSTALL_DIR)
	$(INSTALL_DATA) $(TAPSET_FILES) $(TAPSET_INSTALL_DIR)

uninstall-local:
	@list='$(TAPSET_FILES)'; for p in $$list; do \
	  echo " rm -f '$(TAPSET_INSTALL_DIR)/$$p'"; \
	  rm -f "$(TAPSET_INSTALL_DIR)/$$p"; \
	done

endif
