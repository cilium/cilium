// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/eppolicymap"
	"github.com/cilium/cilium/pkg/maps/sockmap"
)

type mapCreationFunc func(string) error

var mapBuilders = map[string]mapCreationFunc{
	"eppolicymap": eppolicymap.CreateWithName,
	"sockmap":     sockmap.CreateWithName,
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s <type> <path>\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "TYPE :=")
	separator := " "
	for k := range mapBuilders {
		fmt.Fprintf(os.Stderr, "%s%s", separator, strings.ToUpper(k))
		separator = " | "
	}
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(1)
}

func main() {
	if len(os.Args) != 3 {
		usage()
	}

	mapType := os.Args[1]
	createMap, exists := mapBuilders[strings.ToLower(mapType)]
	if !exists {
		fmt.Fprintf(os.Stderr, "Unrecognized map type %s\n", mapType)
		usage()
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stdout, "Failed to configure resource limits: %s\n", err)
	}
	bpf.CheckOrMountFS("")

	bpfObjPath := os.Args[2]
	if err := createMap(bpfObjPath); err != nil {
		fmt.Fprintf(os.Stdout, "Failed to create map: %s\n", err)
	}
}
