all: tests cilium-net

KERNEL:= $(shell uname -s)
MACHINE := $(shell uname -m)

tests:
	go fmt ./*.go
	go test ./*.go

cilium-net:tests
	go build -o cilium-net-${KERNEL}-${MACHINE} ./*.go
