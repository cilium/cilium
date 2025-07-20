include Makefile.defs

.PHONY: all
all: $(TARGET)

.PHONY: $(TARGET)
$(TARGET):
	make -C cmd all

.PHONY: install
install: $(TARGET)
	make -C cmd install

.PHONY: clean
clean:
	make -C cmd clean

.PHONY: test
test:
	$(GO) test $(GO_TEST_FLAGS) ./...

.PHONY: test-all
test-all: test
	make -C flow test
	make -C cmd test

.PHONY: bench
bench:
	$(GO) test $(GO_BENCH_FLAGS) $$($(GO) list ./...)

.PHONY: bench-all
bench-all: bench
	make -C flow bench
	make -C cmd bench

.PHONY: check
ifneq (,$(findstring $(GOLANGCILINT_WANT_VERSION),$(GOLANGCILINT_VERSION)))
check:
	golangci-lint run
else
check:
	docker run --rm -v `pwd`:/app -w /app docker.io/golangci/golangci-lint:v$(GOLANGCILINT_WANT_VERSION) golangci-lint run
endif

.PHONY: check-all
check-all: check
	make -C flow check
	make -C cmd check
