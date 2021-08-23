// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cilium/cilium-cli/internal/cli/cmd"

	gops "github.com/google/gops/agent"
)

func main() {
	if err := gops.Listen(gops.Options{}); err != nil {
		log.Printf("Unable to start gops: %s", err)
	}

	if err := cmd.NewDefaultCiliumCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
