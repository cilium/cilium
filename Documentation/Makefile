# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = Cilium
SOURCEDIR     = .
BUILDDIR      = _build

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

.PHONY: help Makefile check-requirements

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile check-requirements
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
