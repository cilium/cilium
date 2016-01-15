mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(notdir $(patsubst %/,%,$(dir $(mkfile_path))))
SOCKET_PATH=${current_dir}

all: tests

tests:
	godep go fmt ./...
	godep go test ./...
