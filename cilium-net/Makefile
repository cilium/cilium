all: tests cilium-net

KERNEL:= $(shell uname -s)
MACHINE := $(shell uname -m)

tests:
	godep go fmt ./*.go
	godep go test ./*.go

cilium-net: tests
	godep go build -o cilium-net-${KERNEL}-${MACHINE} ./*.go
