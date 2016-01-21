all: map_ctrl

tests:
	godep go fmt ./...
	godep go test ./...

SOURCES := $(shell find . -name '*.go')

map_ctrl: $(SOURCES)
	$(MAKE) tests
	godep go build -o map_ctrl

clean:
	rm -f map_ctrl
