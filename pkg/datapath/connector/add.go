// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/sysctl"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "endpoint-connector")

const (
	// hostInterfacePrefix is the Host interface prefix.
	hostInterfacePrefix = "lxc"
	// temporaryInterfacePrefix is the temporary interface prefix while setting up libNetwork interface.
	temporaryInterfacePrefix = "tmp"
)

// Endpoint2IfName returns the host interface name for the given endpointID.
func Endpoint2IfName(endpointID string) string {
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(endpointID)))
	// returned string length should be < unix.IFNAMSIZ
	truncateLength := uint(unix.IFNAMSIZ - len(temporaryInterfacePrefix) - 1)
	return hostInterfacePrefix + truncateString(sum, truncateLength)
}

// Endpoint2TempIfName returns the temporary interface name for the given
// endpointID.
func Endpoint2TempIfName(endpointID string) string {
	return temporaryInterfacePrefix + truncateString(endpointID, 5)
}

// Endpoint2TempRandIfName returns a random, temporary interface name for the
// given endpointID. This is similar to Endpoint2TempIfName() but uses a
// random string instead of endpoint ID.
func Endpoint2TempRandIfName() string {
	return temporaryInterfacePrefix + "_" + rand.RandomLowercaseStringWithLen(5)
}

func truncateString(epID string, maxLen uint) string {
	if maxLen <= uint(len(epID)) {
		return epID[:maxLen]
	}
	return epID
}

// DisableRpFilter tries to disable rpfilter on specified interface
func DisableRpFilter(ifName string) error {
	return sysctl.Disable(fmt.Sprintf("net.ipv4.conf.%s.rp_filter", ifName))
}
