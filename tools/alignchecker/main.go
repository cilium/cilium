// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"

	datapathchecker "github.com/cilium/cilium/pkg/datapath/alignchecker"
	monitorchecker "github.com/cilium/cilium/pkg/monitor/alignchecker"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <path>\n", os.Args[0])
		os.Exit(1)
	}

	bpfObjPath := os.Args[1]
	if _, err := os.Stat(bpfObjPath); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot check alignment against %s: %s\n", bpfObjPath, err)
		os.Exit(1)
	}
	if err := datapathchecker.CheckStructAlignments(bpfObjPath); err != nil {
		fmt.Fprintf(os.Stderr, "C and Go structs alignment check in datapath failed: %s\n", err)
		os.Exit(1)
	}
	if err := monitorchecker.CheckStructAlignments(bpfObjPath); err != nil {
		fmt.Fprintf(os.Stderr, "C and Go structs alignment check in monitor failed: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "OK\n")
}
