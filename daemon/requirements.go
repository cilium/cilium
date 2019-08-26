// Copyright 2016-2019 Authors of Cilium
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

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/versioncheck"
	"golang.org/x/sys/unix"

	go_version "github.com/hashicorp/go-version"
)

var (
	minKernelVer = versioncheck.MustCompile(">= 4.8.0")
	minClangVer  = versioncheck.MustCompile(">= 3.8.0")

	recKernelVer = versioncheck.MustCompile(">= 4.9.0")
	recClangVer  = versioncheck.MustCompile(">= 3.9.0")

	// LLVM/clang version which supports `-mattr=dwarfris`
	dwarfrisClangVer           = versioncheck.MustCompile(">= 7.0.0")
	canDisableDwarfRelocations bool
)

func parseKernelVersion(ver string) (*go_version.Version, error) {
	verStrs := strings.Split(ver, ".")
	switch {
	case len(verStrs) < 2:
		return nil, fmt.Errorf("unable to get kernel version from %q", ver)
	case len(verStrs) < 3:
		verStrs = append(verStrs, "0")
	}
	// We are assuming the kernel version will be something as:
	// 4.9.17-040917-generic

	// If verStrs is []string{ "4", "9", "17-040917-generic" }
	// then we need to retrieve patch number.
	patch := regexp.MustCompilePOSIX(`^[0-9]+`).FindString(verStrs[2])
	if patch == "" {
		verStrs[2] = "0"
	} else {
		verStrs[2] = patch
	}
	return go_version.NewVersion(strings.Join(verStrs[:3], "."))
}

func getKernelVersion() (*go_version.Version, error) {
	var unameBuf unix.Utsname
	if err := unix.Uname(&unameBuf); err != nil {
		log.WithError(err).Fatal("kernel version: NOT OK")
	}
	return parseKernelVersion(string(unameBuf.Release[:]))
}

func getClangVersion(filePath string) (*go_version.Version, error) {
	verOut, err := exec.Command(filePath, "--version").CombinedOutput()
	if err != nil {
		log.WithError(err).Fatal("clang version: NOT OK")
	}
	res := regexp.MustCompile(`(clang version )([^ ]*)`).FindStringSubmatch(string(verOut))
	if len(res) != 3 {
		log.Fatalf("clang version: NOT OK: unable to get clang's version "+
			"from: %q", string(verOut))
	}
	// at this point res is []string{"clang", "version", "maj.min.patch"}
	verStrs := strings.Split(res[2], ".")
	if len(verStrs) < 3 {
		return nil, fmt.Errorf("unable to get clang version from %q", string(verOut))
	}
	v := strings.Join(verStrs[:3], ".")
	// Handle Ubuntu versioning by removing the dash and everything after.
	// F. ex. `4.0.0-1ubuntu1~16 -> 4.0.0` and `3.8.0-2ubuntu4 -> 3.8.0`.
	v = strings.Split(v, "-")[0]
	return go_version.NewVersion(v)
}

func checkBPFLogs(logType string, fatal bool) {
	bpfLogFile := logType + ".log"
	bpfLogPath := filepath.Join(option.Config.StateDir, bpfLogFile)

	if _, err := os.Stat(bpfLogPath); os.IsNotExist(err) {
		log.Infof("%s check: OK!", logType)
	} else if err == nil {
		bpfFeaturesLog, err := ioutil.ReadFile(bpfLogPath)
		if err != nil {
			log.WithError(err).WithField(logfields.Path, bpfLogPath).Fatalf("%s check: NOT OK. Unable to read", logType)
		}
		printer := log.Debugf
		if fatal {
			printer = log.Errorf
			printer("%s check: NOT OK", logType)
		} else {
			printer("%s check: Some features may be limited:", logType)
		}
		lines := strings.Trim(string(bpfFeaturesLog), "\n")
		for _, line := range strings.Split(lines, "\n") {
			printer(line)
		}
		if fatal {
			log.Fatalf("%s check failed.", logType)
		}
	} else {
		log.WithError(err).WithField(logfields.Path, bpfLogPath).Fatalf("%s check: NOT OK. Unable to read", logType)
	}
}

func checkMinRequirements() {
	kernelVersion, err := getKernelVersion()
	if err != nil {
		log.WithError(err).Fatal("kernel version: NOT OK")
	}
	if !minKernelVer.Check(kernelVersion) {
		log.Fatalf("kernel version: NOT OK: minimal supported kernel "+
			"version is %s; kernel version that is running is: %s", minKernelVer, kernelVersion)
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
		if !minClangVer.Check(clangVersion) {
			log.Fatalf("clang version: NOT OK: minimal supported clang "+
				"version is %s; clang version that is running is: %s", minClangVer, clangVersion)
		}
		//clang >= 3.9 / kernel < 4.9 - does not work
		if recClangVer.Check(clangVersion) && !recKernelVer.Check(kernelVersion) {
			log.Fatalf("clang (%s) and kernel (%s) version: NOT OK: please upgrade "+
				"your kernel version to at least %s",
				clangVersion, kernelVersion, recKernelVer)
		}
		canDisableDwarfRelocations = dwarfrisClangVer.Check(clangVersion)
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
		// /usr/include/gnu/stubs-32.h is installed by 'glibc-devel.i686' in fedora
		// /usr/include/sys/cdefs.h is installed by 'libc6-dev-i386' in ubuntu
		// both files exist on both systems but cdefs.h already exists in fedora
		// without 'glibc-devel.i686' so we check for 'stubs-32.h first.
		if _, err := os.Stat("/usr/include/gnu/stubs-32.h"); os.IsNotExist(err) {
			log.Fatal("linking environment: NOT OK, please make sure you have 'glibc-devel.i686' if you use fedora system or 'libc6-dev-i386' if you use ubuntu system")
		}
		if _, err := os.Stat("/usr/include/sys/cdefs.h"); os.IsNotExist(err) {
			log.Fatal("linking environment: NOT OK, please make sure you have 'libc6-dev-i386' in your ubuntu system")
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
	probeScript := filepath.Join(option.Config.BpfDir, "run_probes.sh")
	if err := exec.Command(probeScript, option.Config.BpfDir, option.Config.StateDir).Run(); err != nil {
		log.WithError(err).Fatal("BPF Verifier: NOT OK. Unable to run checker for bpf_features")
	}
	featuresFilePath := filepath.Join(globalsDir, "bpf_features.h")
	if _, err := os.Stat(featuresFilePath); os.IsNotExist(err) {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("BPF Verifier: NOT OK. Unable to read bpf_features.h")
	}

	checkBPFLogs("bpf_requirements", true)
	checkBPFLogs("bpf_features", false)
	bpf.ReadFeatureProbes(featuresFilePath)
}
