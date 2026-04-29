// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// cilium-cloud-dep-check verifies that each operator binary variant only
// contains the cloud-provider SDKs that match its build tags.
//
// It enforces independence across the cilium-operator-* binaries:
//
//   - cilium-operator-generic     : must not contain AWS, Azure, or AlibabaCloud SDKs
//   - cilium-operator-aws         : must not contain Azure or AlibabaCloud SDKs
//   - cilium-operator-azure       : must not contain AWS or AlibabaCloud SDKs
//   - cilium-operator-alibabacloud: must not contain AWS or Azure SDKs
//
// The check is implemented by invoking `go list -deps -tags <tags> ./operator`
// from the cilium repository root and matching the resulting import paths
// against the forbidden module prefixes for that binary.
//
// Usage:
//
//	cilium-cloud-dep-check [-root <repo-root>] [-target <pkg>]
//
// Exit code is non-zero if any forbidden dependency is found.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// cloudSDKs maps a cloud-provider name to the list of import-path prefixes
// owned by that provider's SDK. A package is considered to belong to the
// provider if its import path starts with any of the listed prefixes.
var cloudSDKs = map[string][]string{
	"aws": {
		"github.com/aws/aws-sdk-go-v2",
		"github.com/aws/smithy-go",
	},
	"azure": {
		"github.com/Azure/azure-sdk-for-go",
		"github.com/AzureAD/",
	},
	"alibabacloud": {
		"github.com/aliyun/alibaba-cloud-sdk-go",
	},
}

// binary describes one cilium-operator binary variant.
type binary struct {
	name      string   // human-readable binary name
	buildTags []string // -tags value passed to `go list`
	allowed   []string // cloud SDKs allowed to appear in this binary
}

// binaries is the canonical list of cross-checked binary configurations.
// Keep this in sync with operator/Makefile.
var binaries = []binary{
	{
		name:      "cilium-operator-generic",
		buildTags: []string{"ipam_provider_operator"},
		allowed:   nil,
	},
	{
		name:      "cilium-operator-aws",
		buildTags: []string{"ipam_provider_aws"},
		allowed:   []string{"aws"},
	},
	{
		name:      "cilium-operator-azure",
		buildTags: []string{"ipam_provider_azure"},
		allowed:   []string{"azure"},
	},
	{
		name:      "cilium-operator-alibabacloud",
		buildTags: []string{"ipam_provider_alibabacloud"},
		allowed:   []string{"alibabacloud"},
	},
	{
		name: "cilium-operator (combined)",
		buildTags: []string{
			"ipam_provider_aws",
			"ipam_provider_azure",
			"ipam_provider_operator",
			"ipam_provider_alibabacloud",
		},
		allowed: []string{"aws", "azure", "alibabacloud"},
	},
}

// listDeps runs `go list -deps -tags <tags> <target>` and returns the unique
// list of import paths.
func listDeps(repoRoot, target string, tags []string) ([]string, error) {
	args := []string{"list", "-deps"}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	args = append(args, target)
	cmd := exec.Command("go", args...)
	cmd.Dir = repoRoot
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list failed: %w", err)
	}
	deps := strings.Split(strings.TrimSpace(string(out)), "\n")
	sort.Strings(deps)
	return deps, nil
}

// classify returns the cloud name if pkg belongs to a known cloud SDK, or "".
func classify(pkg string) string {
	for cloud, prefixes := range cloudSDKs {
		for _, p := range prefixes {
			// Strip a trailing slash for prefix-only matches like "AzureAD/".
			trimmed := strings.TrimSuffix(p, "/")
			if pkg == trimmed || strings.HasPrefix(pkg, trimmed+"/") {
				return cloud
			}
		}
	}
	return ""
}

// check verifies a single binary configuration. It returns the list of
// forbidden packages found in its dependency closure.
func check(repoRoot, target string, b binary) (map[string][]string, error) {
	deps, err := listDeps(repoRoot, target, b.buildTags)
	if err != nil {
		return nil, err
	}
	forbidden := map[string][]string{}
	for _, d := range deps {
		cloud := classify(d)
		if cloud == "" {
			continue
		}
		if slices.Contains(b.allowed, cloud) {
			continue
		}
		forbidden[cloud] = append(forbidden[cloud], d)
	}
	return forbidden, nil
}

func main() {
	var (
		repoRoot string
		target   string
	)
	flag.StringVar(&repoRoot, "root", ".", "path to the cilium repository root")
	flag.StringVar(&target, "target", "./operator", "go package to analyze")
	flag.Parse()

	abs, err := filepath.Abs(repoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot resolve repo root %q: %v\n", repoRoot, err)
		os.Exit(2)
	}

	failures := 0
	for _, b := range binaries {
		fmt.Printf("==> checking %s (tags: %s)\n", b.name, strings.Join(b.buildTags, ","))
		forbidden, err := check(abs, target, b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR: %v\n", err)
			failures++
			continue
		}
		if len(forbidden) == 0 {
			fmt.Println("  OK")
			continue
		}
		failures++
		// Stable iteration order for output.
		clouds := make([]string, 0, len(forbidden))
		for k := range forbidden {
			clouds = append(clouds, k)
		}
		sort.Strings(clouds)
		for _, cloud := range clouds {
			pkgs := forbidden[cloud]
			fmt.Printf("  FAIL: forbidden %s SDK packages found (%d):\n", cloud, len(pkgs))
			for _, p := range pkgs {
				fmt.Printf("    - %s\n", p)
			}
		}
	}

	if failures > 0 {
		fmt.Fprintf(os.Stderr, "\ncloud dependency check failed for %d binary configuration(s)\n", failures)
		os.Exit(1)
	}
	fmt.Println("\nall binary configurations are independent")
}
