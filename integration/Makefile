mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(notdir $(patsubst %/,%,$(dir $(mkfile_path))))
SOCKET_PATH=${current_dir}
include ../Makefile.defs

TARGET=integration

all: $(TARGET)

tests:
	go fmt ./...
	sudo -E env "PATH=${PATH}" go test ./...

runtime-tests:

run:

clean:
	rm -f $(TARGET)

$(TARGET):

install:
