all: tests cilium-net-daemon

KERNEL:= $(shell uname -s)
MACHINE := $(shell uname -m)

tests:
	godep go fmt ./...
	godep go test ./...

run:
	./cilium-net-daemon-${KERNEL}-${MACHINE}

cilium-net-daemon: tests
	godep go build -o cilium-net-daemon-${KERNEL}-${MACHINE} ./main.go
