include ../../../Makefile.defs

CWD := $(CURDIR)
VERSION := $(shell echo $(VERSION)|grep -Eo '^([0-9]+\.[0-9]+\.[0-9]+)')

build: clean
	@echo "export VERSION=$(VERSION)" > cfg/envs
	@echo "export COMMIT=$(shell git rev-parse HEAD)" >> cfg/envs
	@echo "export SHORTCOMMIT=$(shell git rev-parse --short HEAD)" >> cfg/envs
	@cd ../../../ &&\
		git archive --format=tar.gz --prefix=cilium-$(shell git rev-parse HEAD)/ -o $(CWD)/cfg/cilium-$(shell git rev-parse --short HEAD).tar.gz HEAD
	@docker build -t cilium:cilium-build-rpm-$(VERSION)-git$(SHORTCOMMIT) cfg/
	@docker run --rm cilium:cilium-build-rpm-$(VERSION)-git$(SHORTCOMMIT) /bin/bash -c \
		'tar -c root/cilium-$(VERSION)*.rpm root/x86_64/cilium-$(VERSION)*.rpm' | tar --strip-components=1 -xvC .

clean:
	ls -d ./* | grep -vE Makefile\|cfg | xargs $(RM) -rf
	ls -d ./cfg/* | grep -vE Dockerfile\|create-rpm.sh\|cilium.spec.envsubst | xargs $(RM) -rf

.PHONY: force build clean
force :;
