// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package verifier_test

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

var (
	ciliumBasePath  = flag.String("cilium-base-path", "", "Cilium checkout base path")
	ciKernelVersion = flag.String("ci-kernel-version", "", "CI kernel version to assume for verifier tests (supported values: 419, 54, netnext)")
)

func getCIKernelVersion(t *testing.T) string {
	t.Helper()

	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatalf("uname: %v", err)
	}

	release := unix.ByteSliceToString(uts.Release[:])

	t.Logf("Detected running kernel version %s", release)

	var ciKernel string
	switch {
	case strings.HasPrefix(release, "4.19"):
		ciKernel = "419"
	case strings.HasPrefix(release, "5.4"):
		ciKernel = "54"
	case strings.HasPrefix(release, "bpf-next"):
		ciKernel = "netnext"
	default:
		t.Fatalf("kernel version %s not supported by verifier complexity tests", release)
	}
	return ciKernel
}

func getDatapathConfigFile(t *testing.T, ciKernelVersion, bpfProgram string) string {
	t.Helper()

	return filepath.Join(*ciliumBasePath, "bpf", "complexity-tests", ciKernelVersion, fmt.Sprintf("%s.txt", bpfProgram))
}

func TestVerifier(t *testing.T) {
	flag.Parse()

	if ciliumBasePath == nil || *ciliumBasePath == "" {
		t.Skip("Please set -cilium-base-path to run verifier tests")
	}
	t.Logf("Cilium checkout base path: %s", *ciliumBasePath)

	var kernelVersion, source string
	if ciKernelVersion != nil && *ciKernelVersion != "" {
		kernelVersion = *ciKernelVersion
		source = "cli"
	} else {
		kernelVersion = getCIKernelVersion(t)
		source = "detected"
	}
	t.Logf("CI kernel version: %s (%s)", kernelVersion, source)

	const (
		HookTC     = "TC"
		HookCgroup = "CG"
		HookXDP    = "XDP"
	)

	for _, bpfProgram := range []struct {
		name      string
		hook      string
		macroName string
	}{
		{
			name:      "bpf_lxc",
			hook:      HookTC,
			macroName: "MAX_LXC_OPTIONS",
		},
		{
			name:      "bpf_host",
			hook:      HookTC,
			macroName: "MAX_HOST_OPTIONS",
		},
		{
			name:      "bpf_xdp",
			hook:      HookXDP,
			macroName: "MAX_XDP_OPTIONS",
		},
		{
			name:      "bpf_overlay",
			hook:      HookTC,
			macroName: "MAX_OVERLAY_OPTIONS",
		},
	} {
		t.Run(bpfProgram.name, func(t *testing.T) {
			file, err := os.Open(getDatapathConfigFile(t, kernelVersion, bpfProgram.name))
			if err != nil {
				t.Fatalf("Unable to open list of datapath configurations for %s: %v", bpfProgram.name, err)
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				datapathConfig := scanner.Text()

				t.Logf("Cleaning %s build files", bpfProgram.name)
				cmd := exec.Command("make", "-C", "bpf/", "clean")
				cmd.Dir = *ciliumBasePath
				if err := cmd.Run(); err != nil {
					t.Fatalf("Failed to clean bpf objects: %v", err)
				}

				t.Logf("Building %s object file", bpfProgram.name)
				cmd = exec.Command("make", "-C", "bpf", fmt.Sprintf("%s.o", bpfProgram.name))
				cmd.Dir = *ciliumBasePath
				cmd.Env = append(cmd.Env,
					fmt.Sprintf("%s=%s", bpfProgram.macroName, datapathConfig),
					fmt.Sprintf("KERNEL=%s", kernelVersion),
				)
				if err := cmd.Run(); err != nil {
					t.Fatalf("Failed to compile %s bpf objects: %v", bpfProgram.name, err)
				}

				t.Logf("Running the verifier test script with %s", bpfProgram.name)
				cmd = exec.Command("./test/bpf/verifier-test.sh")
				cmd.Dir = *ciliumBasePath
				cmd.Env = append(cmd.Env,
					"TC_PROGS=",
					"XDP_PROGS=",
					"CG_PROGS=",
					fmt.Sprintf("%s_PROGS=%s", bpfProgram.hook, bpfProgram.name),
				)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Errorf("Failed to load BPF program %s: %v\ndatapath configuration: %s\ncommand output: %s", bpfProgram.name, err, datapathConfig, out)
				}
			}

			if err = scanner.Err(); err != nil {
				t.Fatalf("Error while reading list of datapath configuration for %s: %v", bpfProgram.name, err)
			}
		})
	}
}
