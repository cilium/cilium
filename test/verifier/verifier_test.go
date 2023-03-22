// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package verifier_test

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
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

// This test tries to compile BPF programs with a set of options that maximize
// size & complexity (as defined in bpf/complexity-tests). Programs are then
// loaded into the kernel to detect complexity & other verifier-related
// regressions.
func TestVerifier(t *testing.T) {
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

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

	for _, bpfProgram := range []struct {
		name      string
		macroName string
	}{
		{
			name:      "bpf_lxc",
			macroName: "MAX_LXC_OPTIONS",
		},
		{
			name:      "bpf_host",
			macroName: "MAX_HOST_OPTIONS",
		},
		{
			name:      "bpf_xdp",
			macroName: "MAX_XDP_OPTIONS",
		},
		{
			name:      "bpf_overlay",
			macroName: "MAX_OVERLAY_OPTIONS",
		},
		{
			name:      "bpf_sock",
			macroName: "MAX_LB_OPTIONS",
		},
	} {
		file, err := os.Open(getDatapathConfigFile(t, kernelVersion, bpfProgram.name))
		if err != nil {
			t.Fatalf("Unable to open list of datapath configurations for %s: %v", bpfProgram.name, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for i := 1; scanner.Scan(); i++ {
			datapathConfig := scanner.Text()

			t.Run(fmt.Sprintf("%s_%d", bpfProgram.name, i), func(t *testing.T) {
				cmd := exec.Command("make", "-C", "bpf/", "clean")
				cmd.Dir = *ciliumBasePath
				if err := cmd.Run(); err != nil {
					t.Fatalf("Failed to clean bpf objects: %v", err)
				}

				cmd = exec.Command("make", "-C", "bpf", fmt.Sprintf("%s.o", bpfProgram.name))
				cmd.Dir = *ciliumBasePath
				cmd.Env = append(cmd.Env,
					fmt.Sprintf("%s=%s", bpfProgram.macroName, datapathConfig),
					fmt.Sprintf("KERNEL=%s", kernelVersion),
				)
				if err := cmd.Run(); err != nil {
					t.Fatalf("Failed to compile %s bpf objects: %v", bpfProgram.name, err)
				}

				spec, err := bpf.LoadCollectionSpec(path.Join(*ciliumBasePath, "bpf", fmt.Sprintf("%s.o", bpfProgram.name)))
				if err != nil {
					t.Fatal(err)
				}

				// Strip all pinning flags so we don't need to specify a pin path
				// and all maps are guaranteed to be created by the ELF.
				for _, m := range spec.Maps {
					m.Pinning = 0
				}

				coll, err := bpf.LoadCollection(spec, ebpf.CollectionOptions{
					// Enable verifier logs for successful loads as well.
					Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch},
				})
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					t.Fatalf("Verifier error: %+v\n\nDatapath build config: %s", ve, datapathConfig)
				}
				if err != nil {
					t.Fatal(err)
				}

				// Print verifier stats, e.g. 'processed 12248 insns (limit 1000000) ...'.
				for n, p := range coll.Programs {
					t.Logf("%s: %s", n, p.VerifierLog)
				}

				coll.Close()
			})

			if err = scanner.Err(); err != nil {
				t.Fatalf("Error while reading list of datapath configurations for %s: %v", bpfProgram.name, err)
			}
		}
	}
}
