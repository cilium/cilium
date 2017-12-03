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

render:
	-docker rm -f docs-cilium >/dev/null
	cd .. && \
	docker run -ti -v $$(pwd):/srv/ cilium/docs-builder /bin/bash -c 'make html' && \
	docker run -dit --name docs-cilium -p 8080:80 -v $$(pwd)/Documentation/_build/html/:/usr/local/apache2/htdocs/ httpd:2.4
	@echo "$$(tput setaf 2)Running at http://localhost:8080$$(tput sgr0)"

cmdref:
	# We don't know what changed so recreate the directory
	-rm -rvf $(CMDREFDIR) && mkdir $(CMDREFDIR)
	${CILIUMDIR}/cilium cmdref -d $(CMDREFDIR)
	${AGENTDIR}/cilium-agent --cmdref $(CMDREFDIR)

.PHONY: help Makefile check-requirements cmdref

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile check-requirements
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
