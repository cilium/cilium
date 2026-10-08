// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package version

import (
	"fmt"
	"os/exec"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/clustermesh-apiserver/etcdinit"
	"github.com/cilium/cilium/pkg/version"
)

func NewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("Cilium ClusterMesh: %s\n", version.Version)
			fmt.Printf("etcd: %s\n", getEtcdVersion())
		},
	}
}

func getEtcdVersion() string {
	out, err := exec.Command(etcdinit.EtcdBinaryLocation, "--version").Output()
	if err != nil {
		return fmt.Sprintf("unable to retrieve version: %s", err)
	}

	const pattern = `etcd Version: (?P<version>.*?)\nGit SHA: (?P<sha>.*?)\nGo Version: (?P<go>.*?)\nGo OS\/Arch: (?P<arch>.*?)\n`
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(string(out), 1)
	if len(matches) != 1 {
		return "unable to parse version"
	}

	return fmt.Sprintf("%s %s go version %s %s",
		matches[0][re.SubexpIndex("version")],
		matches[0][re.SubexpIndex("sha")],
		matches[0][re.SubexpIndex("go")],
		matches[0][re.SubexpIndex("arch")],
	)
}
