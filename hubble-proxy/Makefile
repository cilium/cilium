TARGET=hubble-proxy
GIT_BRANCH != which git >/dev/null 2>&1 && git rev-parse --abbrev-ref HEAD
GIT_HASH != which git >/dev/null 2>&1 && git rev-parse --short HEAD

TEST_TIMEOUT ?= 5s

all: hubble-proxy

hubble-proxy:
	go build -ldflags "-X 'github.com/cilium/cilium/pkg/hubble/proxy.GitBranch=${GIT_BRANCH}' -X 'github.com/cilium/cilium/pkg/hubble/proxy.GitHash=$(GIT_HASH)'" -o $(TARGET)

clean:
	rm -f $(TARGET)

test:
	go test -timeout=$(TEST_TIMEOUT) -race -cover $$(go list ./...)

bench:
	go test -timeout=$(TEST_TIMEOUT) -bench=. $$(go list ./...)

vet:
	go vet $$(go list ./...)

.PHONY: all hubble-proxy clean test bench vet
