GO := CGO_ENABLED=0 go
GO_TAGS ?=
TARGET=cilium

$(TARGET):
	$(GO) build $(if $(GO_TAGS),-tags $(GO_TAGS)) \
		-ldflags "-w -s" \
		-o $(TARGET) \
		./cmd/cilium

.PHONY: $(TARGET)
