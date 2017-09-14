TEST?=./...
VERSION = $(shell awk -F\" '/^const Version/ { print $$2; exit }' version.go)
GITSHA:=$(shell git rev-parse HEAD)
GITBRANCH:=$(shell git symbolic-ref --short HEAD 2>/dev/null)

default: test

# bin generates the releasable binaries
bin: generate deps
	@sh -c "'$(CURDIR)/scripts/build.sh'"

# cov generates the coverage output
cov: generate deps
	gocov test ./... | gocov-html > /tmp/coverage.html
	open /tmp/coverage.html

# dev creates binaries for testing locally - these are put into ./bin and
# $GOPATH
dev: generate deps
	@SERF_DEV=1 sh -c "'$(CURDIR)/scripts/build.sh'"

# dist creates the binaries for distibution
dist: #bin
	@sh -c "'$(CURDIR)/scripts/dist.sh' $(VERSION)"

# subnet sets up the require subnet for testing on darwin (osx) - you must run
# this before running other tests if you are on osx.
subnet:
	@sh -c "'$(CURDIR)/scripts/setup_test_subnet.sh'"

# test runs the test suite
test: subnet generate deps
	go list $(TEST) | xargs -n1 go test $(TESTARGS)

# testrace runs the race checker
testrace: subnet generate deps
	go test -race $(TEST) $(TESTARGS)

# deps installs all the dependencies needed to test, build, and run
deps:
	go get github.com/mitchellh/gox
	go get -v -d -t ./...

# `go get -u` causes git to revert Serf to the master branch. This causes all
# kinds of headaches. We record the git sha when make starts try to correct it
# if we detect dift. DO NOT use `git checkout -f` for this because it will wipe
# out your changes without asking.
updatedeps:
	@echo "INFO: Currently on $(GITBRANCH) ($(GITSHA))"
	@git diff-index --quiet HEAD ; if [ $$? -ne 0 ]; then \
		echo "ERROR: Your git working tree has uncommitted changes. updatedeps will fail. Please stash or commit your changes first."; \
		exit 1; \
	fi
	go get -u github.com/mitchellh/gox
	go list ./... \
		| xargs go list -f '{{join .Deps "\n"}}' \
		| grep -v github.com/hashicorp/serf \
		| grep -v '/internal/' \
		| sort -u \
		| xargs go get -f -u -v -d 
	@if [ "$(GITBRANCH)" != "" ]; then git checkout -q $(GITBRANCH); else git checkout -q $(GITSHA); fi
	@if [ `git rev-parse HEAD` != "$(GITSHA)" ]; then \
		echo "ERROR: git checkout has drifted and we weren't able to correct it. Was $(GITBRANCH) ($(GITSHA))"; \
		exit 1; \
	fi
	@echo "INFO: Currently on $(GITBRANCH) ($(GITSHA))"

# generate runs `go generate` to build the dynamically generated source files
generate:
	find . -type f -name '.DS_Store' -delete
	go generate ./...

.PHONY: default bin cov deps dev dist subnet test testrace updatedeps generate
