// Copyright 2017 Authors of Cilium
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

package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/maps/tunnel"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

// configCmd represents the config command
var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Reset the agent state",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cleanup")
		runCleanup()
	},
}

var force bool

const (
	ciliumLinkPrefix = "cilium_"
	hostLinkPrefix   = "lxc"
	hostLinkLen      = len(hostLinkPrefix + "XXXXX")
	cniConfigV1      = "/etc/cni/net.d/10-cilium-cni.conf"
	cniConfigV2      = "/etc/cni/net.d/00-cilium-cni.conf"
	cniConfigV3      = "/etc/cni/net.d/05-cilium-cni.conf"
)

func init() {
	rootCmd.AddCommand(cleanupCmd)
	cleanupCmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation")
}

func runCleanup() {
	// Abort if the agent is running, err == nil is handled correctly by Stat.
	if _, err := os.Stat(defaults.PidFilePath); !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Agent should not be running when cleaning up\n"+
			"Found pidfile %s\n", defaults.PidFilePath)
		os.Exit(1)
	}

	routes, links, err := findRoutesAndLinks()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	}

	showWhatWillBeRemoved(routes, links)
	if !force && !confirmCleanup() {
		return
	}

	// ENOENT and similar errors are ignored. Should print all other
	// errors seen, but continue.  So that one remove function does not
	// prevent the remaining from running.
	type cleanupFunc func() error
	checks := []cleanupFunc{removeAllMaps, removeDirs, removeCNI}
	for _, clean := range checks {
		if err := clean(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		}
	}

	if err := removeRoutesAndLinks(routes, links); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	}
}

func showWhatWillBeRemoved(routes map[int]netlink.Route, links map[int]netlink.Link) {
	fmt.Printf("Warning: Destructive operation. You are about to remove:\n"+
		"- all BPF maps in %s containing '%s' and '%s'\n"+
		"- mounted bpffs at %s\n"+
		"- library code in %s\n"+
		"- endpoint state in %s\n"+
		"- CNI configuration at %s, %s, %s\n",
		bpf.MapPrefixPath(), ciliumLinkPrefix, tunnel.MapName, bpf.GetMapRoot(),
		defaults.LibraryPath, defaults.RuntimePath, cniConfigV1, cniConfigV2, cniConfigV3)

	if len(routes) > 0 {
		fmt.Printf("- routes\n")
		for _, v := range routes {
			fmt.Printf("%v\n", v)
		}
	}

	if len(links) > 0 {
		fmt.Println("- links")
		for _, v := range links {
			fmt.Printf("%v\n", v)
		}
	}
}

func confirmCleanup() bool {
	fmt.Printf("The command is non-revertible, do you want to continue [y/N]?\n")
	var res string
	fmt.Scanln(&res)
	return res == "y"
}

func removeCNI() error {
	os.Remove(cniConfigV1)
	os.Remove(cniConfigV2)

	err := os.Remove(cniConfigV3)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func removeDirs() error {
	dirs := []string{defaults.RuntimePath, defaults.LibraryPath}
	for _, dir := range dirs {
		// In the unlikely case one of the constants is the root directory, abort.
		if dir == "/" {
			return fmt.Errorf("will not remove root directory %s", dir)
		}
		if err := os.RemoveAll(dir); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
	}
	return nil
}

func removeAllMaps() error {
	mapDir := bpf.MapPrefixPath()
	maps, err := ioutil.ReadDir(mapDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, m := range maps {
		name := m.Name()
		// Skip non Cilium looking maps
		if !strings.HasPrefix(name, ciliumLinkPrefix) && name != tunnel.MapName {
			continue
		}
		if err = os.Remove(filepath.Join(mapDir, name)); err != nil {
			return err
		}
		fmt.Printf("removed map %s\n", m.Name())
	}
	return err
}

func linkMatch(linkName string) bool {
	return strings.HasPrefix(linkName, ciliumLinkPrefix) ||
		strings.HasPrefix(linkName, hostLinkPrefix) && len(linkName) == hostLinkLen
}

func findRoutesAndLinks() (map[int]netlink.Route, map[int]netlink.Link, error) {
	routesToRemove := map[int]netlink.Route{}
	linksToRemove := map[int]netlink.Link{}

	if routes, err := netlink.RouteList(nil, netlink.FAMILY_V4); err == nil {
		for _, r := range routes {
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				if strings.Contains(err.Error(), "Link not found") {
					continue
				}
				return routesToRemove, linksToRemove, err
			}

			linkName := link.Attrs().Name
			if !linkMatch(linkName) {
				continue
			}
			routesToRemove[r.LinkIndex] = r
			linksToRemove[link.Attrs().Index] = link
		}
	}

	if links, err := netlink.LinkList(); err == nil {
		for _, link := range links {
			linkName := link.Attrs().Name
			if !linkMatch(linkName) {
				continue
			}
			linksToRemove[link.Attrs().Index] = link
		}
	}
	return routesToRemove, linksToRemove, nil
}

func removeRoutesAndLinks(routes map[int]netlink.Route, links map[int]netlink.Link) error {
	for _, route := range routes {
		if err := netlink.RouteDel(&route); err != nil {
			return err
		}
		fmt.Printf("removed route %v\n", route)
	}

	for _, link := range links {
		if err := netlink.LinkDel(link); err != nil {
			if strings.Contains(err.Error(), "Link not found") ||
				strings.Contains(err.Error(), "no such device") {
				continue
			}
			return err
		}
		fmt.Printf("removed link %s\n", link.Attrs().Name)
	}
	return nil
}
