// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"os"

	"github.com/cilium/cilium/bugtool/cmd"

	log "github.com/sirupsen/logrus"
)

func main() {
	if err := cmd.BugtoolRootCmd.Execute(); err != nil {
		log.WithError(err).Fatal("failed to run root command")
		os.Exit(1)
	}
}
