// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package node

import (
	"os"
	"strings"

	"github.com/cilium/cilium/pkg/option"
)

func initLocalBootID() {
	bootID, err := os.ReadFile(option.Config.BootIDFile)
	if err != nil {
		log.WithError(err).Warnf("Could not read boot id from %s", option.Config.BootIDFile)
		return
	}
	localBootID = strings.TrimSpace(string(bootID))
	log.Infof("Local boot ID is %q", localBootID)
}
