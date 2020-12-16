// Copyright 2020 Authors of Cilium
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
	"os"
	"regexp"
	"text/tabwriter"

	"github.com/blang/semver/v4"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Args:  cobra.NoArgs,
	Short: "Check development setup",
	Run:   rootCmdRun,
}

var (
	backportingChecks *bool
	nfsFirewallChecks *bool
)

func init() {
	flags := rootCmd.Flags()
	backportingChecks = flags.Bool("backporting", false, "run backporting checks")
	nfsFirewallChecks = flags.Bool("nfs-firewall", false, "run extra NFS firewall checks, requires root privileges")
}

func rootCmdRun(cmd *cobra.Command, args []string) {
	minGoVersion, err := semver.ParseTolerant(minGoVersionStr)
	if err != nil {
		panic(fmt.Sprintf("cannot parse minGoVersionStr: %q", minGoVersionStr))
	}

	checks := []check{
		osArchCheck{},
		unameCheck{},
		&binaryCheck{
			name:          "make",
			ifNotFound:    checkError,
			versionArgs:   []string{"--version"},
			versionRegexp: regexp.MustCompile(`GNU\s+Make\s+(\d+\.\d+\S*)`),
		},
		&binaryCheck{
			name:          "go",
			ifNotFound:    checkError,
			versionArgs:   []string{"version"},
			versionRegexp: regexp.MustCompile(`go version go(\d+\.\d+\S*)`),
			minVersion:    &minGoVersion,
		},
		&binaryCheck{
			name:          "clang",
			ifNotFound:    checkError,
			versionArgs:   []string{"--version"},
			versionRegexp: regexp.MustCompile(`clang version (\d+\.\d+\.\d+)`),
			minVersion:    &semver.Version{Major: 10, Minor: 0, Patch: 0},
		},
		// FIXME add libelf-devel check?
		&binaryCheck{
			name:          "ginkgo",
			ifNotFound:    checkWarning,
			versionArgs:   []string{"version"},
			versionRegexp: regexp.MustCompile(`Ginkgo Version (\d+\.\d+\S*)`),
			minVersion:    &semver.Version{Major: 1, Minor: 4, Patch: 0},
			hint:          `Run "go get -u github.com/onsi/ginkgo/ginkgo".`,
		},
		// FIXME add gomega check?
		&binaryCheck{
			name:          "golangci-lint",
			ifNotFound:    checkWarning,
			versionArgs:   []string{"version"},
			versionRegexp: regexp.MustCompile(`(\d+\.\d+\S*)`),
			minVersion:    &semver.Version{Major: 1, Minor: 27, Patch: 0},
			hint:          "See https://golangci-lint.run/usage/install/#local-installation.",
		},
		&binaryCheck{
			name:          "docker",
			ifNotFound:    checkError,
			versionArgs:   []string{"--version"},
			versionRegexp: regexp.MustCompile(`Docker version (\d+\.\d+\.\d+)`),
		},
		&binaryCheck{
			name:          "helm",
			ifNotFound:    checkWarning,
			versionArgs:   []string{"version"},
			versionRegexp: regexp.MustCompile(`Version:"v(\d+\.\d+\.\d+)"`),
			minVersion:    &semver.Version{Major: 3, Minor: 0, Patch: 0},
		},
		&binaryCheck{
			name:          "llc",
			ifNotFound:    checkWarning,
			versionArgs:   []string{"--version"},
			versionRegexp: regexp.MustCompile(`LLVM\s+version\s+(\d+\.\d+\S*)`),
			minVersion:    &semver.Version{Major: 10, Minor: 0, Patch: 0},
		},
		&binaryCheck{
			name:          "vagrant",
			ifNotFound:    checkInfo,
			versionArgs:   []string{"--version"},
			versionRegexp: regexp.MustCompile(`Vagrant (\d+\.\d+\S*)`),
			minVersion:    &semver.Version{Major: 2, Minor: 0, Patch: 0},
		},
		&binaryCheck{
			name:           "virtualbox",
			alternateNames: []string{"VirtualBox"},
			ifNotFound:     checkInfo,
		},
		&binaryCheck{
			name:           "vboxheadless",
			alternateNames: []string{"VBoxHeadless"},
			ifNotFound:     checkInfo,
			versionArgs:    []string{"--version"},
			versionRegexp:  regexp.MustCompile(`Oracle VM VirtualBox Headless Interface (\d+\.\d+\.\d+\S*)`),
		},
		&binaryCheck{
			name:          "pip3",
			ifNotFound:    checkWarning,
			versionArgs:   []string{"--version"},
			versionRegexp: regexp.MustCompile(`pip (\d+\.\d+\S*)`),
		},
		dockerGroupCheck{},
	}

	if *backportingChecks {
		checks = append(checks,
			&binaryCheck{
				name:       "jq",
				ifNotFound: checkError,
			},
			&binaryCheck{
				name:          "python3",
				ifNotFound:    checkError,
				versionArgs:   []string{"--version"},
				versionRegexp: regexp.MustCompile(`Python\s+(\d+.\d+\.\d+)`),
				minVersion:    &semver.Version{Major: 3, Minor: 6, Patch: 0},
			},
			&commandCheck{
				name:             "pygithub",
				command:          "python3",
				args:             []string{"-c", "from github import Github"},
				ifFailure:        checkWarning,
				ifSuccessMessage: "pygithub installed",
				hint:             `Run "pip3 install --user PyGithub".`,
			},
			&binaryCheck{
				name:          "hub",
				ifNotFound:    checkError,
				versionArgs:   []string{"--version"},
				versionRegexp: regexp.MustCompile(`hub\s+version\s+(\d+.\d+\.\d+)`),
				minVersion:    &semver.Version{Major: 2, Minor: 0, Patch: 0},
			},
			&envVarCheck{
				name:            "GITHUB_TOKEN",
				ifNotSetOrEmpty: checkInfo,
			},
		)
	}

	if *nfsFirewallChecks {
		checks = append(checks,
			etcNFSConfCheck{},
			&iptablesRuleCheck{
				rule: []string{"INPUT", "-p", "tcp", "-s", "192.168.34.0/24", "--dport", "111", "-j", "ACCEPT"},
			},
			&iptablesRuleCheck{
				rule: []string{"INPUT", "-p", "tcp", "-s", "192.168.34.0/24", "--dport", "2049", "-j", "ACCEPT"},
			},
			&iptablesRuleCheck{
				rule: []string{"INPUT", "-p", "tcp", "-s", "192.168.34.0/24", "--dport", "20048", "-j", "ACCEPT"},
			},
		)
	}

	worstResult := checkOK
	resultWriter := tabwriter.NewWriter(os.Stdout, 3, 0, 3, ' ', 0)
	fmt.Fprint(resultWriter, "RESULT\tCHECK\tMESSAGE\n")
	hints := make([]string, 0, len(checks))
	for _, check := range checks {
		checkResult, message := check.Run()
		fmt.Fprintf(resultWriter, "%s\t%s\t%s\n", checkResultStr[checkResult], check.Name(), message)
		if checkResult > checkOK {
			if hint := check.Hint(); hint != "" {
				hints = append(hints, fmt.Sprintf("%s\t%s\n", check.Name(), hint))
			}
		}
		if checkResult > worstResult {
			worstResult = checkResult
		}
	}
	resultWriter.Flush()

	if len(hints) > 0 {
		fmt.Println()
		hintWriter := tabwriter.NewWriter(os.Stdout, 3, 0, 3, ' ', 0)
		fmt.Fprint(hintWriter, "CHECK\tHINT\n")
		for _, hint := range hints {
			fmt.Fprint(hintWriter, hint)
		}
		hintWriter.Flush()
	}

	if worstResult > checkOK {
		fmt.Println()
		fmt.Println("See https://docs.cilium.io/en/latest/contributing/development/dev_setup/.")
		if *backportingChecks {
			fmt.Println("See https://docs.cilium.io/en/latest/contributing/release/backports/.")
		}
	}

	if worstResult > checkWarning {
		os.Exit(1)
	}
}
