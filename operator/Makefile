# GOBUILD relies on the order of makefile list to get VERSION file
include ../Makefile.defs

TARGET=cilium-operator
SOURCES := $(shell find ../pkg . \( -name '*.go'  ! -name '*_test.go' \))
$(TARGET): $(SOURCES)
	@$(ECHO_GO)
	$(QUIET)$(GO) build $(GOBUILD) -o $(TARGET)

all: $(TARGET)

clean:
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	$(QUIET)rm -f $(TARGET)
	$(GO) clean

install:
