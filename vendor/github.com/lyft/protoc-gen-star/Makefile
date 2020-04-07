# the name of this package & all subpackages
PKG  := $(shell go list .)
PKGS := $(shell go list ./...)

.PHONY: bootstrap
bootstrap: vendor testdata # set up the project for development

.PHONY: lint
lint: # lints the package for common code smells
	set -e; for f in `find . -name "*.go" -not -name "*.pb.go" | grep -v vendor`; do \
		out=`gofmt -s -d $$f`; \
		test -z "$$out" || (echo $$out && exit 1); \
	done
	which golint || go get -u golang.org/x/lint/golint
	golint -set_exit_status $(PKGS)
	go vet -all -shadow -shadowstrict $(PKGS)

.PHONY: quick
quick: vendor testdata # runs all tests without the race detector or coverage
	go test $(PKGS)

.PHONY: tests
tests: vendor testdata # runs all tests against the package with race detection and coverage percentage
	go test -race -cover $(PKGS)

.PHONY: cover
cover: vendor testdata # runs all tests against the package, generating a coverage report and opening it in the browser
	go test -race -covermode=atomic -coverprofile=cover.out $(PKGS) || true
	go tool cover -html cover.out -o cover.html
	open cover.html

.PHONY: docs
docs: # starts a doc server and opens a browser window to this package
	(sleep 2 && open http://localhost:6060/pkg/$(PKG)/) &
	godoc -http=localhost:6060

.PHONY: testdata
testdata: testdata-graph testdata-go testdata/generated testdata/fdset.bin # generate all testdata

.PHONY: testdata-graph
testdata-graph: bin/protoc-gen-debug # parses the proto file sets in testdata/graph and renders binary CodeGeneratorRequest
	set -e; for subdir in `find ./testdata/graph -type d -mindepth 1 -maxdepth 1`; do \
		protoc -I ./testdata/graph \
			--plugin=protoc-gen-debug=./bin/protoc-gen-debug \
			--debug_out="$$subdir:$$subdir" \
			`find $$subdir -name "*.proto"`; \
	done

testdata/generated: protoc-gen-go bin/protoc-gen-example
	which protoc-gen-go || (go install github.com/golang/protobuf/protoc-gen-go)
	rm -rf ./testdata/generated && mkdir -p ./testdata/generated
	# generate the official go code, must be one directory at a time
	set -e; for subdir in `find ./testdata/protos -type d -mindepth 1`; do \
		files=`find $$subdir -name "*.proto" -maxdepth 1`; \
		[ ! -z "$$files" ] && \
		protoc -I ./testdata/protos \
			--go_out="$$GOPATH/src" \
			$$files; \
	done
	# generate using our demo plugin, don't need to go directory at a time
	set -e; for subdir in `find ./testdata/protos -type d -mindepth 1 -maxdepth 1`; do \
		protoc -I ./testdata/protos \
			--plugin=protoc-gen-example=./bin/protoc-gen-example \
			--example_out="paths=source_relative:./testdata/generated" \
			`find $$subdir -name "*.proto"`; \
	done

testdata/fdset.bin:
	@protoc -I ./testdata/protos \
		-o ./testdata/fdset.bin \
		--include_imports \
		testdata/protos/**/*.proto

.PHONY: testdata-go
testdata-go: protoc-gen-go bin/protoc-gen-debug # generate go-specific testdata
	cd lang/go && $(MAKE) \
		testdata-names \
		testdata-packages \
		testdata-outputs

vendor: # install project dependencies
	which glide || (curl https://glide.sh/get | sh)
	glide install

.PHONY: protoc-gen-go
protoc-gen-go:
	which protoc-gen-go || (go get -u github.com/golang/protobuf/protoc-gen-go)

bin/protoc-gen-example: vendor # creates the demo protoc plugin for demonstrating uses of PG*
	go build -o ./bin/protoc-gen-example ./testdata/protoc-gen-example

bin/protoc-gen-debug: vendor # creates the protoc-gen-debug protoc plugin for output ProtoGeneratorRequest messages
	go build -o ./bin/protoc-gen-debug ./protoc-gen-debug

.PHONY: clean
clean:
	rm -rf vendor
	rm -rf bin
	rm -rf testdata/generated
	set -e; for f in `find . -name *.pb.bin`; do \
		rm $$f; \
	done
	set -e; for f in `find . -name *.pb.go`; do \
		rm $$f; \
	done
