package main

import (
	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
)

func main() {
	spec, err := ebpf.LoadCollectionSpec("test/tc/bpf_host.o")
	if err != nil {
		panic(err)
	}

	logging.DefaultLogger.SetLevel(logrus.DebugLevel)

	err = bpf.RemoveUnreachableTailcalls(spec)
	if err != nil {
		panic(err)
	}
}
