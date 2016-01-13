all: tests cilium-net-client

KERNEL:= $(shell uname -s)
MACHINE := $(shell uname -m)

tests:
	godep go fmt ./*.go
	godep go test ./*.go

cilium-net-client:tests
	godep go build -o cilium-net-client-${KERNEL}-${MACHINE} ./*.go
