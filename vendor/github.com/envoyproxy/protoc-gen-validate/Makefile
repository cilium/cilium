empty :=
space := $(empty) $(empty)
PACKAGE := github.com/envoyproxy/protoc-gen-validate

# protoc-gen-go parameters for properly generating the import path for PGV
VALIDATE_IMPORT := Mvalidate/validate.proto=${PACKAGE}/validate
GO_IMPORT_SPACES := ${VALIDATE_IMPORT},\
	Mgoogle/protobuf/any.proto=github.com/golang/protobuf/ptypes/any,\
	Mgoogle/protobuf/duration.proto=github.com/golang/protobuf/ptypes/duration,\
	Mgoogle/protobuf/struct.proto=github.com/golang/protobuf/ptypes/struct,\
	Mgoogle/protobuf/timestamp.proto=github.com/golang/protobuf/ptypes/timestamp,\
	Mgoogle/protobuf/wrappers.proto=github.com/golang/protobuf/ptypes/wrappers,\
	Mgoogle/protobuf/descriptor.proto=github.com/golang/protobuf/protoc-gen-go/descriptor,\
	Mgogoproto/gogo.proto=${PACKAGE}/gogoproto
GO_IMPORT:=$(subst $(space),,$(GO_IMPORT_SPACES))

# protoc-gen-gogo parameters
GOGO_IMPORT_SPACES := ${VALIDATE_IMPORT},\
	Mgoogle/protobuf/any.proto=github.com/gogo/protobuf/types,\
	Mgoogle/protobuf/duration.proto=github.com/gogo/protobuf/types,\
	Mgoogle/protobuf/struct.proto=github.com/gogo/protobuf/types,\
	Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,\
	Mgoogle/protobuf/wrappers.proto=github.com/gogo/protobuf/types,\
	Mgoogle/protobuf/descriptor.proto=github.com/gogo/protobuf/types,\
	Mgogoproto/gogo.proto=github.com/gogo/protobuf/gogoproto
GOGO_IMPORT:=$(subst $(space),,$(GOGO_IMPORT_SPACES))

.PHONY: build
build: validate/validate.pb.go
	# generates the PGV binary and installs it into $$GOPATH/bin
	go install .

.PHONY: bazel
bazel:
	# generate the PGV plugin with Bazel
	bazel build //tests/... --incompatible_new_actions_api=false

.PHONY: build_generation_tests
build_generation_tests:
	bazel build //tests/generation/...

.PHONY: gazelle
gazelle: vendor
	# runs gazelle against the codebase to generate Bazel BUILD files
	bazel run //:gazelle -- -go_prefix=github.com/envoyproxy/protoc-gen-validate
	buildozer 'replace deps //vendor/github.com/golang/protobuf/proto:go_default_library @com_github_golang_protobuf//proto:go_default_library' '//...:%go_library'
	buildozer 'replace deps @com_github_golang_protobuf//ptypes:go_default_library_gen @com_github_golang_protobuf//ptypes:go_default_library' '//...:%go_library'
	buildozer 'replace deps @io_bazel_rules_go//proto/wkt:duration_go_proto @com_github_golang_protobuf//ptypes/duration:go_default_library' '//...:%go_library'
	buildozer 'replace deps @io_bazel_rules_go//proto/wkt:timestamp_go_proto @com_github_golang_protobuf//ptypes/timestamp:go_default_library' '//...:%go_library'
	buildozer 'replace deps //vendor/github.com/gogo/protobuf/proto:go_default_library @com_github_gogo_protobuf//proto:go_default_library' '//...:%go_library'
	buildozer 'replace deps //vendor/github.com/gogo/protobuf/types:go_default_library @com_github_gogo_protobuf//types:go_default_library' '//...:%go_library'

vendor:
	dep ensure -v -update

.PHONY: lint
lint:
	# lints the package for common code smells
	which golint || go get -u golang.org/x/lint/golint
	which shadow || go get -u golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow
	test -z "$(gofmt -d -s ./*.go)" || (gofmt -d -s ./*.go && exit 1)
	# golint -set_exit_status
	# check for variable shadowing
	go vet -vettool=$(which shadow) *.go

gogofast:
	go build -o $@ vendor/github.com/gogo/protobuf/protoc-gen-gogofast/main.go

.PHONY: harness
harness: testcases tests/harness/go/harness.pb.go tests/harness/gogo/harness.pb.go tests/harness/go/main/go-harness tests/harness/gogo/main/go-harness tests/harness/cc/cc-harness
 	# runs the test harness, validating a series of test cases in all supported languages
	go run ./tests/harness/executor/*.go -go -gogo -cc

.PHONY: bazel-harness
bazel-harness:
	# runs the test harness via bazel
	bazel run //tests/harness/executor:executor --incompatible_new_actions_api=false -- -go -gogo -cc -java -python

.PHONY: testcases
testcases: gogofast
	# generate the test harness case protos
	rm -r tests/harness/cases/go || true
	mkdir tests/harness/cases/go
	rm -r tests/harness/cases/other_package/go || true
	mkdir tests/harness/cases/other_package/go
	rm -r tests/harness/cases/gogo || true
	mkdir tests/harness/cases/gogo
	rm -r tests/harness/cases/other_package/gogo || true
	mkdir tests/harness/cases/other_package/gogo
	# protoc-gen-go makes us go a package at a time
	cd tests/harness/cases/other_package && \
	protoc \
		-I . \
		-I ../../../.. \
		--go_out="${GO_IMPORT}:./go" \
		--plugin=protoc-gen-gogofast=$(shell pwd)/gogofast \
		--gogofast_out="${GOGO_IMPORT}:./gogo" \
		--validate_out="lang=go:./go" \
		--validate_out="lang=gogo:./gogo" \
		./*.proto
	cd tests/harness/cases && \
	protoc \
		-I . \
		-I ../../.. \
		--go_out="Mtests/harness/cases/other_package/embed.proto=${PACKAGE}/tests/harness/cases/other_package/go,${GO_IMPORT}:./go" \
		--plugin=protoc-gen-gogofast=$(shell pwd)/gogofast \
		--gogofast_out="Mtests/harness/cases/other_package/embed.proto=${PACKAGE}/tests/harness/cases/other_package/gogo,${GOGO_IMPORT}:./gogo" \
		--validate_out="lang=go,Mtests/harness/cases/other_package/embed.proto=${PACKAGE}/tests/harness/cases/other_package/go:./go" \
		--validate_out="lang=gogo,Mtests/harness/cases/other_package/embed.proto=${PACKAGE}/tests/harness/cases/other_package/gogo:./gogo" \
		./*.proto

tests/harness/go/harness.pb.go:
	# generates the test harness protos
	cd tests/harness && protoc -I . \
		--go_out="${GO_IMPORT}:./go" harness.proto

tests/harness/gogo/harness.pb.go: gogofast
	# generates the test harness protos
	cd tests/harness && protoc -I . \
		--plugin=protoc-gen-gogofast=$(shell pwd)/gogofast \
		--gogofast_out="${GOGO_IMPORT}:./gogo" harness.proto

tests/harness/go/main/go-harness:
	# generates the go-specific test harness
	go build -o ./tests/harness/go/main/go-harness ./tests/harness/go/main

tests/harness/gogo/main/go-harness:
	# generates the gogo-specific test harness
	go build -o ./tests/harness/gogo/main/go-harness ./tests/harness/gogo/main

tests/harness/cc/cc-harness: tests/harness/cc/harness.cc
	# generates the C++-specific test harness
	# use bazel which knows how to pull in the C++ common proto libraries
	bazel build //tests/harness/cc:cc-harness
	cp bazel-bin/tests/harness/cc/cc-harness $@
	chmod 0755 $@

tests/harness/java/java-harness:
	# generates the Java-specific test harness
	mvn -q -f java/pom.xml clean package -DskipTests

.PHONY: ci
ci: lint bazel testcases bazel-harness build_generation_tests

.PHONY: clean
clean:
	(which bazel && bazel clean) || true
	rm -f \
		gogofast \
		tests/harness/cc/cc-harness \
		tests/harness/go/main/go-harness \
		tests/harness/gogo/main/go-harness \
		tests/harness/gogo/harness.pb.go \
		tests/harness/gogo/harness.pb.go \
		tests/harness/go/harness.pb.go
	rm -rf \
		tests/harness/cases/go \
		tests/harness/cases/other_package/go \
		tests/harness/cases/gogo \
		tests/harness/cases/other_package/gogo \
