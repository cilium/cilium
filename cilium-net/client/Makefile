all: tests cilium-net-client

KERNEL:= $(shell uname -s)
MACHINE := $(shell uname -m)

tests:
	go fmt ./*.go
	go test ./*.go

cilium-net-client:tests
	go build -o cilium-net-client-${KERNEL}-${MACHINE} ./*.go
