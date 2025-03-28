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

func initLocalBootID(logger *slog.Logger) {
	bootID, err := os.ReadFile(option.Config.BootIDFile)
	if err != nil {
		logger.Warn("Could not read boot id from file",
			logfields.Error, err,
			logfields.File, option.Config.BootIDFile,
		)
		return
	}
	localBootID = strings.TrimSpace(string(bootID))
	logger.Info("Local boot ID",
		logfields.BootID, localBootID,
	)
}
