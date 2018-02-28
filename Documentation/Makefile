# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = Cilium
SOURCEDIR     = .
BUILDDIR      = _build
CMDREFDIR     = cmdref
CILIUMDIR     = ../cilium
AGENTDIR      = ../daemon
HEALTHDIR     = ../cilium-health

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

PIP_REQUIREMENTS = \
	sphinx \
	sphinxcontrib-httpdomain \
	sphinxcontrib-openapi \
	sphinx-rtd-theme \
	sphinx-tabs \
	recommonmark

check-requirements:
	@$(foreach PKG,$(PIP_REQUIREMENTS), \
		pip list --format=json | grep ${PKG} > /dev/null || \
		(echo "Documentation dependency '${PKG}' not installed."; \
			echo "Run 'pip install ${PKG}'"; \
			exit 1); \
	)

cmdref:
	# We don't know what changed so recreate the directory
	-rm -rvf $(CMDREFDIR)/cilium*
	${CILIUMDIR}/cilium cmdref -d $(CMDREFDIR)
	${AGENTDIR}/cilium-agent --cmdref $(CMDREFDIR)
	${HEALTHDIR}/cilium-health --cmdref $(CMDREFDIR)

.PHONY: help Makefile check-requirements cmdref

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile check-requirements
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
