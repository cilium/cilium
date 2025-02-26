// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package node

import (
	"log/slog"
	"os"
	"strings"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

func initLocalBootID() {
	bootID, err := os.ReadFile(option.Config.BootIDFile)
	if err != nil {
		log.Warn("Could not read boot id from file", slog.Any(logfields.Error, err), slog.String("file", option.Config.BootIDFile))
		return
	}
	localBootID = strings.TrimSpace(string(bootID))
	log.Info("Local boot ID", slog.String("boot-id", localBootID))
}
