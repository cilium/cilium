// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configuration

import (
	"fmt"

	"github.com/cilium/cilium/pkg/mountinfo"
)

func bpffsMountpoint() (string, error) {
	mountInfos, err := mountinfo.GetMountInfo()
	if err != nil {
		return "", fmt.Errorf("failed to get mount info: %w", err)
	}

	// To determine the mountpoint of the BPF fs we iterate through the list
	// of mount info (i.e. /proc/self/mounts entries) and return the first
	// one which has the "bpf" fs type and the "/" root.
	//
	// The root == "/" condition allows us to ignore all BPF fs which are
	// sub mounts (such as for example /sys/fs/bpf/{xdp, ip, sk, sa}) of the
	// one with the "/" root.
	//
	// Moreover, as Cilium will refuse to start if there are multiple BPF fs
	// which have "/" as their root, we can assume there will be at most one
	// mountpoint which matches the conditions and so we return it as soon
	// as we find it.
	for _, mountInfo := range mountInfos {
		if mountInfo.FilesystemType == "bpf" && mountInfo.Root == "/" {
			return mountInfo.MountPoint, nil
		}
	}

	return "", fmt.Errorf("could not found bpf filesystem in mount info")
}
