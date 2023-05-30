export GOBIN ?= $(shell pwd)/bin

GOLINT = $(GOBIN)/golint
STATICCHECK = $(GOBIN)/staticcheck

BENCH_FLAGS ?= -cpuprofile=cpu.pprof -memprofile=mem.pprof -benchmem

GO_FILES = $(shell \
	find . '(' -path '*/.*' -o -path './vendor' ')' -prune \
	-o -name '*.go' -print | cut -b3-)

MODULES = . ./tools

.PHONY: all
all: build lint test

.PHONY: build
build:
	go build ./...

.PHONY: install
install:
	$(foreach dir,$(MODULES),( \
		cd $(dir) && \
		go mod download) && \
	) true

.PHONY: lint
lint: $(GOLINT) $(STATICCHECK)
	@rm -rf lint.log
	@echo "Checking formatting..."
	@gofmt -d -s $(GO_FILES) 2>&1 | tee lint.log
	@echo "Checking vet..."
	@go vet ./... 2>&1 | tee -a lint.log
	@echo "Checking lint..."
	@$(GOLINT) ./... 2>&1 | tee -a lint.log
	@echo "Checking staticcheck..."
	@$(STATICCHECK) ./... 2>&1 | tee -a lint.log
	@echo "Checking for unresolved FIXMEs..."
	@git grep -i fixme | grep -v -e Makefile | tee -a lint.log
	@echo "Checking for license headers..."
	@./check_license.sh | tee -a lint.log
	@[ ! -s lint.log ]

$(GOLINT): tools/go.mod
	cd tools && go install golang.org/x/lint/golint

$(STATICCHECK): tools/go.mod
	cd tools && go install honnef.co/go/tools/cmd/staticcheck

.PHONY: test
test:
	go test -race ./...

.PHONY: cover
cover:
	go test -race -coverprofile=cover.out -coverpkg=./... ./...
	go tool cover -html=cover.out -o cover.html

.PHONY: bench
BENCH ?= .
bench:
	go list ./... | xargs -n1 go test -bench=$(BENCH) -run="^$$" $(BENCH_FLAGS)

.PHONY: tidy
tidy:
	$(foreach dir,$(MODULES),(cd $(dir) && go mod tidy) &&) true
