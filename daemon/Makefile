# We keep track of the SHA over bindata.go plus the go version used to
# generate the bindata.go as it affects the generated code. A change
# of version is likely causing a SHA conflict as well.
include bpf.sha

# GOBUILD relies on the order of makefile list to get VERSION file
include ../Makefile.defs


GO_BINDATA := $(QUIET) go-bindata -prefix ../ -mode 0640 -modtime 1450269211 \
	-ignore Makefile -ignore bpf_features.h -ignore lxc_config.h \
	-ignore netdev_config.h -ignore node_config.h -ignore filter_config.h \
	-ignore '.+\.o$$' -ignore '.+\.orig$$' -ignore '.+~$$' \
	-ignore '\.DS_Store' -pkg daemon

all: check-bindata

.PHONY: check-bindata
check-bindata: bindata.go
	@$(ECHO_CHECK) ../contrib/scripts/bindata.sh
	$(QUIET) ../contrib/scripts/bindata.sh $(GO_BINDATA_SHA1SUM)

apply-bindata: go-bindata
	@$(ECHO_GEN)bpf.sha
	$(QUIET) ../contrib/scripts/bindata.sh apply

bindata.go go-bindata: $(BPF_FILES)
	@$(ECHO_GEN) $@
	$(GO_BINDATA) -o ./bindata.go $(BPF_FILES)
