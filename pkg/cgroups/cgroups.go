// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cgroups

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var (
	// Path to where cgroup is mounted
	cgroupRoot = defaults.DefaultCgroupRoot

	// Only mount a single instance
	cgrpMountOnce sync.Once
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cgroups")

// setCgroupRoot will set the path to mount cgroupv2
func setCgroupRoot(path string) {
	cgroupRoot = path
}

// GetCgroupRoot returns the path for the cgroupv2 mount
func GetCgroupRoot() string {
	return cgroupRoot
}

// getCgroupRootForKind tries to determine a cgroup v2 root path for attaching
// the BPF cgroup programs when Cilium is running on Kind. The determined path
// is not used for mounting, and it is set to "cgroupRoot" after the mounting
// has succeeded.
//
// When running on Kind, each k8s node runs in a separate non-host netns container
// on the same host. This means, that there might be multiple cilium-agent
// instances on the single host. When bpf_sock LB is enabled, each cilium-agent
// would try to attach the program to the same cgroup v2 root. In such case,
// the bpf_sock based LB would not work because the program would try to access
// the same LB BPF map which is not shared among Kind nodes.
//
// To fix this, we need to attach the program to cgroup v2 root of each Kind node.
// Pods on a Kind node belong to a cgroup v2 which name format is the following:
//
//		0::/system.slice/docker-$(SOME_NODE_ID).scope/kubelet/kubepods/burstable/pod-$(SOME_POD_ID)
//
// So if we attach the program to "$(CGROUP_MOUNT_DIR)/system.slice/docker-$(SOME_NODE_ID).scope/kubelet/",
// it's guaranteed that it will be run for all pods on that node.
//
// However, there is one problem when net_cls or net_prio of the legacy cgroup (v1)
// is enabled together with cgroup v2. If any of these controllers store class_id
// or prioridx (which is the case for Docker) in the socket cgroup data struct,
// the kernel won't be able to retrieve the exact root, and it will fallback to
// the default hierarchy of cgroup v2 (aka the mount path) [1]. This renders the
// programs attached in a sub-hierarchy ineffective.
//
// [1]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/cgroup.h?h=v5.10#n837
func getCgroupRootForKind() (string, error) {
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	defer f.Close()

	cgroupPath := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "net_cls") || strings.Contains(line, "net_prio") {
			return "", fmt.Errorf("cgroups v1 net_cls or net_prio detected which interferes with cgroup v2")
		}

		if strings.HasPrefix(line, "0::") { // cgroup v2 starts with "0::"
			re := regexp.MustCompile(`^.*kubelet`)
			p := path.Join(cgroupRoot, strings.Split(line, "::")[1])
			match := re.FindString(p)
			if match == "" {
				return "", fmt.Errorf("cannot find \"kubelet\" in cgroup v2 path: %q", p)
			}
			cgroupPath = match
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	if cgroupPath == "" {
		return "", fmt.Errorf("cgroup v2 not found")
	}

	return cgroupPath, nil
}

// CheckOrMountCgrpFS this checks if the cilium cgroup2 root mount point is
// mounted and if not mounts it. If mapRoot is "" it will mount the default
// location. It is harmless to have multiple cgroupv2 root mounts so unlike
// BPFFS case we simply mount at the cilium default regardless if the system
// has another mount created by systemd or otherwise.
//
// runsOnKind indicates whether cilium-agent runs on Kind (see getCgroupRootForKind
// for details).
func CheckOrMountCgrpFS(mapRoot string, runsOnKind bool) {
	cgrpMountOnce.Do(func() {
		if mapRoot == "" {
			mapRoot = cgroupRoot
		}
		err := cgrpCheckOrMountLocation(mapRoot)
		// Failed cgroup2 mount is not a fatal error, sockmap will be disabled however
		if err == nil {
			log.Infof("Mounted cgroupv2 filesystem at %s", mapRoot)

			if runsOnKind {
				p, err := getCgroupRootForKind()
				if err != nil {
					log.WithError(err).
						Warnf("Failed to determine cgroup v2 hierarchy for Kind node. Socket-based LB (--%s) will not work.",
							option.EnableHostReachableServices)
				} else {
					setCgroupRoot(p)
				}
			}
		}
	})
}
