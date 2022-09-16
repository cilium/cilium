// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/cilium/pkg/versioncheck"
)

const (
	minKernelVer = "4.8.0"
	minClangVer  = "3.8.0"
	recKernelVer = "4.9.0"
	recClangVer  = "3.9.0"
)

var (
	isMinKernelVer = versioncheck.MustCompile(">=" + minKernelVer)
	isMinClangVer  = versioncheck.MustCompile(">=" + minClangVer)

	isRecKernelVer = versioncheck.MustCompile(">=" + recKernelVer)
	isRecClangVer  = versioncheck.MustCompile(">=" + recClangVer)
)

func getClangVersion(filePath string) (semver.Version, error) {
	verOut, err := exec.Command(filePath, "--version").CombinedOutput()
	if err != nil {
		log.WithError(err).Fatal("clang version: NOT OK")
	}
	res := regexp.MustCompile(`(clang version )([^\s]*)`).FindStringSubmatch(string(verOut))
	if len(res) != 3 {
		log.Fatalf("clang version: NOT OK: unable to get clang's version "+
			"from: %q", string(verOut))
	}
	// at this point res is []string{"clang", "version", "maj.min.patch"}
	verStrs := strings.Split(res[2], ".")
	if len(verStrs) < 3 {
		return semver.Version{}, fmt.Errorf("unable to get clang version from %q", string(verOut))
	}
	v := strings.Join(verStrs[:3], ".")
	// Handle Ubuntu versioning by removing the dash and everything after.
	// F. ex. `4.0.0-1ubuntu1~16 -> 4.0.0` and `3.8.0-2ubuntu4 -> 3.8.0`.
	v = strings.Split(v, "-")[0]
	return versioncheck.Version(v)
}

// CheckMinRequirements checks that minimum kernel requirements are met for
// configuring the BPF datapath. If not, fatally exits.
func CheckMinRequirements() {
	kernelVersion, err := version.GetKernelVersion()
	if err != nil {
		log.WithError(err).Fatal("kernel version: NOT OK")
	}
	if !isMinKernelVer(kernelVersion) {
		log.Fatalf("kernel version: NOT OK: minimal supported kernel "+
			"version is %s; kernel version that is running is: %s", minKernelVer, kernelVersion)
	}

	_, err = netlink.RuleList(netlink.FAMILY_V4)
	if errors.Is(err, unix.EAFNOSUPPORT) {
		log.WithError(err).Error("Policy routing:NOT OK. " +
			"Please enable kernel configuration item CONFIG_IP_MULTIPLE_TABLES")
	}

	if option.Config.EnableIPv6 {
		if _, err := os.Stat("/proc/net/if_inet6"); os.IsNotExist(err) {
			log.Fatalf("kernel: ipv6 is enabled in agent but ipv6 is either disabled or not compiled in the kernel")
		}
	}

	if filePath, err := exec.LookPath("clang"); err != nil {
		log.WithError(err).Fatal("clang: NOT OK")
	} else {
		clangVersion, err := getClangVersion(filePath)
		if err != nil {
			log.WithError(err).Fatal("clang: NOT OK")
		}
		if !isMinClangVer(clangVersion) {
			log.Fatalf("clang version: NOT OK: minimal supported clang "+
				"version is %s; clang version that is running is: %s", minClangVer, clangVersion)
		}
		//clang >= 3.9 / kernel < 4.9 - does not work
		if isRecClangVer(clangVersion) && !isRecKernelVer(kernelVersion) {
			log.Fatalf("clang (%s) and kernel (%s) version: NOT OK: please upgrade "+
				"your kernel version to at least %s",
				clangVersion, kernelVersion, recKernelVer)
		}
		log.Infof("clang (%s) and kernel (%s) versions: OK!", clangVersion, kernelVersion)
	}

	if filePath, err := exec.LookPath("llc"); err != nil {
		log.WithError(err).Fatal("llc: NOT OK")
	} else {
		lccVersion, err := exec.Command(filePath, "--version").CombinedOutput()
		if err == nil {
			if strings.Contains(strings.ToLower(string(lccVersion)), "debug") {
				log.Warn("llc version was compiled in debug mode, expect higher latency!")
			}
		}
		log.Info("linking environment: OK!")
	}

	globalsDir := option.Config.GetGlobalsDir()
	if err := os.MkdirAll(globalsDir, defaults.StateDirRights); err != nil {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("Could not create runtime directory")
	}
	if err := os.Chdir(option.Config.LibDir); err != nil {
		log.WithError(err).WithField(logfields.Path, option.Config.LibDir).Fatal("Could not change to runtime directory")
	}
	if _, err := os.Stat(option.Config.BpfDir); os.IsNotExist(err) {
		log.WithError(err).Fatalf("BPF template directory: NOT OK. Please run 'make install-bpf'")
	}

	// bpftool checks
	if !option.Config.DryMode {
		probeManager := probes.NewProbeManager()

		// VTEP integration feature requires kernel 1m large instruction support
		if option.Config.EnableVTEP {
			if probes.HaveLargeInstructionLimit() != nil {
				log.Fatalf("VXLAN Tunnel Endpoint (VTEP) Integration: requires support for large programs (Linux 5.2.0 or newer)")
			}
		}
		if err := probeManager.SystemConfigProbes(); err != nil {
			errMsg := "BPF system config check: NOT OK."
			// TODO(vincentmli): revisit log when GH#14314 has been resolved
			// Warn missing required kernel config option
			log.WithError(err).Warn(errMsg)
		}
		if err := probes.CreateHeaderFiles(filepath.Join(option.Config.BpfDir, "include/bpf"), probes.ExecuteHeaderProbes()); err != nil {
			log.WithError(err).Fatal("failed to create header files with feature macros")
		}
	}
}
