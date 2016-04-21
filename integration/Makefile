mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(notdir $(patsubst %/,%,$(dir $(mkfile_path))))
SOCKET_PATH=${current_dir}
include ../Makefile.defs

TARGET=integration

all: $(TARGET)

tests:
	godep go fmt ./...
	godep go test ./...

runtime-tests:

run:

clean:
	rm -f $(TARGET)

$(TARGET):

install:
