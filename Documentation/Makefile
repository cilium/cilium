include ../Makefile.quiet

.PHONY: default clean builder-image cmdref epub latex html run-server stop-server

default: html

clean:
	-$(QUIET)rm -rf _build

builder-image:
	$(QUIET)tar c requirements.txt Dockerfile \
	  | docker build --tag cilium/docs-builder -

DOCKER_RUN := docker container run --rm \
		--workdir /src/Documentation \
		--volume $(CURDIR)/..:/src \
		--user "$(shell id -u):$(shell id -g)" \
			cilium/docs-builder

cmdref:
	@$(ECHO_GEN)cmdref
	-$(QUIET)rm -rvf ${cmdref}/cilium*
	$(QUIET)$(DOCKER_RUN) ./update-cmdrefs.sh

epub latex html: builder-image
	@$(ECHO_GEN)_api
	$(QUIET)cp -r ../api _api
	@$(ECHO_GEN)_build/$@
	$(QUIET)$(DOCKER_RUN) ./check-build.sh $(@)

DOCS_PORT = 9081

run-server: stop-server
	$(QUIET)docker container run --rm \
		--detach \
		--interactive \
		--tty \
		--name docs-cilium \
		--publish $(DOCS_PORT):80 \
		--volume $(CURDIR)/_build/html/:/usr/local/apache2/htdocs/ \
			httpd:2.4
	@echo "$$(tput setaf 2)Running at http://localhost:$(DOCS_PORT)$$(tput sgr0)"

stop-server:
	-$(QUIET)docker container rm --force --volumes docs-cilium
