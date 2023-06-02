// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"text/tabwriter"

	"github.com/blang/semver/v4"
	"github.com/spf13/cobra"
	"golang.org/x/mod/modfile"
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
	backportingChecks = flags.Bool("backporting", false, "Run backporting checks")
	nfsFirewallChecks = flags.Bool("nfs-firewall", false, "Run extra NFS firewall checks, requires root privileges")
}

func readGoModGoVersion(rootDir string) (*semver.Version, error) {
	goModFile := "go.mod"
	path := filepath.Join(rootDir, goModFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	mod, err := modfile.Parse(goModFile, data, nil)
	if err != nil {
		return nil, err
	}

	if mod.Go == nil {
		return nil, fmt.Errorf("no go statement found in %s", path)
	}
	ver, err := semver.ParseTolerant(mod.Go.Version)
	if err != nil {
		return nil, err
	}
	return &ver, nil
}

func rootCmdRun(cmd *cobra.Command, args []string) {
	rootDir := goPath() + "/src/github.com/cilium/cilium"

	// $GOPATH is optional to set with a module-based Go setup
	// If we cannot find src path via `$GOPATH`, just look in
	// the `make` dir for `go.mod`
	if _, err := os.Stat(rootDir); os.IsNotExist(err) {
		rootDir, _ = os.Getwd()
	}

	minGoVersion, err := readGoModGoVersion(rootDir)
	if err != nil {
		panic(fmt.Sprintf("cannot read go version from go.mod: %v", err))
	}

	checks := []check{
		osArchCheck{},
		unameCheck{},
		rootDirCheck{
			rootDir: rootDir,
		},
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
			minVersion:    minGoVersion,
		},
		&binaryCheck{
			name:          "tparse",
			ifNotFound:    checkWarning,
			versionArgs:   []string{"-v"},
			versionRegexp: regexp.MustCompile(`tparse version: v(\d+\.\d+\.\d+)`),
			hint:          `Run "go install github.com/mfridman/tparse@latest"`,
		},
		&binaryCheck{
			name:          "clang",
			ifNotFound:    checkError,
			versionArgs:   []string{"--version"},
			versionRegexp: regexp.MustCompile(`clang version (\d+\.\d+\.\d+)`),
			minVersion:    &semver.Version{Major: 10, Minor: 0, Patch: 0},
		},
		&binaryCheck{
			name:          "docker-server",
			command:       "docker",
			ifNotFound:    checkWarning,
			versionArgs:   []string{"version", "--format", "{{ .Server.Version }}"},
			versionRegexp: regexp.MustCompile(`(\d+\.\d+\.\d+)`),
		},
		&binaryCheck{
			name:          "docker-client",
			command:       "docker",
			ifNotFound:    checkWarning,
			versionArgs:   []string{"version", "--format", "{{ .Client.Version }}"},
			versionRegexp: regexp.MustCompile(`(\d+\.\d+\.\d+)`),
		},
		&binaryCheck{
			name:          "docker-buildx",
			command:       "docker",
			ifNotFound:    checkWarning,
			versionArgs:   []string{"buildx", "version"},
			versionRegexp: regexp.MustCompile(`github\.com/docker/buildx v?(\d+\.\d+\.\d+)`),
			hint:          "see https://docs.docker.com/buildx/working-with-buildx/",
		},
		&binaryCheck{
			name:          "ginkgo",
			ifNotFound:    checkWarning,
			versionArgs:   []string{"version"},
			versionRegexp: regexp.MustCompile(`Ginkgo Version (\d+\.\d+\S*)`),
			minVersion:    &semver.Version{Major: 1, Minor: 4, Patch: 0},
			maxVersion:    &semver.Version{Major: 2, Minor: 0, Patch: 0},
			hint:          `Run "go install github.com/onsi/ginkgo/ginkgo@latest".`,
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
			minVersion:    &semver.Version{Major: 3, Minor: 6, Patch: 0},
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
			hint:           "run \"VBoxHeadless --help\" to diagnose why vboxheadless failed to execute",
		},
		&binaryCheck{
			name:          "pip3",
			ifNotFound:    checkWarning,
			versionArgs:   []string{"--version"},
			versionRegexp: regexp.MustCompile(`pip (\d+\.\d+\S*)`),
		},
		&binaryCheck{
			name:          "cfssl",
			ifNotFound:    checkWarning,
			versionArgs:   []string{"version"},
			versionRegexp: regexp.MustCompile(`Version: (.*)`),
			hint:          "See https://github.com/cloudflare/cfssl#installation.",
		},
		&binaryCheck{
			name:          "cfssljson",
			ifNotFound:    checkWarning,
			versionArgs:   []string{"-version"},
			versionRegexp: regexp.MustCompile(`Version: (.*)`),
			hint:          "See https://github.com/cloudflare/cfssl#installation.",
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
				minVersion:    &semver.Version{Major: 2, Minor: 14, Patch: 0},
				hint:          `Download the latest version from https://github.com/github/hub/releases.`,
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
				rule: []string{"INPUT", "-p", "tcp", "-s", "192.168.61.0/24", "--dport", "111", "-j", "ACCEPT"},
			},
			&iptablesRuleCheck{
				rule: []string{"INPUT", "-p", "tcp", "-s", "192.168.61.0/24", "--dport", "2049", "-j", "ACCEPT"},
			},
			&iptablesRuleCheck{
				rule: []string{"INPUT", "-p", "tcp", "-s", "192.168.61.0/24", "--dport", "20048", "-j", "ACCEPT"},
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
