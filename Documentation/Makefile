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

check-requirements:
	@pip list --format=json | grep sphinxcontrib-httpdomain > /dev/null || \
	 (echo "sphinxcontrib-httpdomain not installed."; \
	  echo "Run pip install sphinxcontrib-httpdomain";  \
	  exit 1)
	@pip list --format=json | grep sphinxcontrib-openapi > /dev/null || \
	 (echo "sphinxcontrib-openapi not installed."; \
	  echo "Run: pip install sphinxcontrib-openapi"; \
	  exit 1)
	@pip list --format=json | grep sphinx-rtd-theme> /dev/null || \
	 (echo "sphinx-rtd-theme not installed."; \
	  echo "Run pip install sphinx-rtd-theme";  \
	  exit 1)
	@pip list --format=json | grep sphinx-tabs> /dev/null || \
	 (echo "sphinx-tabs not installed."; \
	  echo "Run pip install sphinx-tabs";  \
	  exit 1)
	@pip list --format=json | grep recommonmark> /dev/null || \
	 (echo "recommonmark not installed."; \
	  echo "Run pip install recommonmark";  \
	  exit 1)

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
