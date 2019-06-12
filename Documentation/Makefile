# Minimal makefile for Sphinx documentation
#
include ../Makefile.quiet

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = Cilium
SOURCEDIR     = .
BUILDDIR      = _build
CMDREFDIR     = cmdref
CILIUMDIR     = ../cilium
AGENTDIR      = ../daemon
BUGTOOLDIR    = ../bugtool
HEALTHDIR     = ../cilium-health
SPELLING_LIST = spelling_wordlist.txt

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

PIP_REQUIREMENTS = $(shell cat requirements.txt | sed -e 's/==.*//g' -e 's/\n/ /g')

check-requirements:
	@set -e;								\
	$(ECHO_CHECK) documentation dependencies...;				\
	PYPKGS=$$(pip3 freeze);							\
	for pkg in ${PIP_REQUIREMENTS}; do					\
		echo $${PYPKGS} | grep -q $${pkg}				\
		|| (echo "Documentation dependency '$${pkg}' not found.";	\
		    echo "Run 'pip3 install --user -r Documentation/requirements.txt'";	\
		    exit 2);							\
	done

cmdref:
	$(QUIET) # We don't know what changed so recreate the directory
	$(QUIET) -rm -rvf $(CMDREFDIR)/cilium*
	@$(ECHO_GEN)cmdref/cilium
	$(QUIET) ${CILIUMDIR}/cilium cmdref -d $(CMDREFDIR)
	@$(ECHO_GEN)cmdref/cilium-bugtool
	$(QUIET) ${BUGTOOLDIR}/cilium-bugtool cmdref -d $(CMDREFDIR)
	@$(ECHO_GEN)cmdref/cilium-agent
	$(QUIET) ${AGENTDIR}/cilium-agent --cmdref $(CMDREFDIR)
	@$(ECHO_GEN)cmdref/cilium-health
	$(QUIET) ${HEALTHDIR}/cilium-health --cmdref $(CMDREFDIR)

# Touch "$@.ok" if the docs build succeeds. Fail if there are errors
# or output other than those including the following phrases:
# "tabs assets" - These are always printed by the spelling check.
# "misspelled words" - These will be explicitly checked below.
# Finally, fail out if we can't remove the file that marks success.
check-build: check-requirements
	@$(ECHO_CHECK) documentation build...
	$(QUIET)! ($(SPHINXBUILD) -b spelling -d "$(BUILDDIR)/doctrees" "$(SOURCEDIR)" "$(BUILDDIR)/spelling" -q -E $(SPHINXOPTS) && touch $@.ok) \
		| grep -v -e "tabs assets" -e "misspelled words"
	@if [ "$$(wc -l < "$(BUILDDIR)/spelling/output.txt")" -ne "0" ]; then \
		echo "Please fix the following spelling mistakes:"; \
		sed 's/^/* Documentation\//' $(BUILDDIR)/spelling/output.txt; \
		echo "If the words are not misspelled, add them to Documentation/$(SPELLING_LIST)."; \
		exit 1; \
	fi
	@rm $@.ok 2>/dev/null

# To use checklinks with `make render-docs`,
# edit the line `%: Makefile check-requirements check-build checklinks`
checklinks:
	$(QUIET)$(SPHINXBUILD) -b linkcheck -d "$(BUILDDIR)/doctrees" "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS)

.PHONY: help Makefile ../Makefile.quiet check-requirements cmdref

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile check-requirements check-build
	@$(ECHO_GEN)_build/$@
	$(QUIET)$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
