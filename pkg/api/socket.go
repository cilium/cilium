// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2020 Authors of Cilium

package api

import (
	"fmt"
	"os"
	"os/user"
	"strconv"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "api")

// getGroupIDByName returns the group ID for the given grpName.
func getGroupIDByName(grpName string) (int, error) {
	group, err := user.LookupGroup(grpName)
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(group.Gid)
}

// SetDefaultPermissions sets the given socket's group to `CiliumGroupName` and
// mode to `SocketFileMode`.
func SetDefaultPermissions(socketPath string) error {
	gid, err := getGroupIDByName(CiliumGroupName)
	if err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.Path: socketPath,
			"group":        CiliumGroupName,
		}).Info("Group not found")
	} else {
		if err := os.Chown(socketPath, 0, gid); err != nil {
			return fmt.Errorf("failed while setting up %s's group ID"+
				" in %q: %s", CiliumGroupName, socketPath, err)
		}
	}
	if err := os.Chmod(socketPath, SocketFileMode); err != nil {
		return fmt.Errorf("failed while setting up %s's file"+
			" permissions in %q: %s", CiliumGroupName, socketPath, err)
	}
	return nil
}
