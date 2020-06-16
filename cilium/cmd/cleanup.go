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

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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

var (
	cleanAll bool
	cleanBPF bool
	force    bool
	runPath  string
)

const (
	allFlagName     = "all-state"
	bpfFlagName     = "bpf-state"
	forceFlagName   = "force"
	runPathFlagName = "run-path"

	cleanCiliumEnvVar = "CLEAN_CILIUM_STATE"
	cleanBpfEnvVar    = "CLEAN_CILIUM_BPF_STATE"

	tcFilterParentIngress = 0xfffffff2
	tcFilterParentEgress  = 0xfffffff3
)

const (
	ciliumLinkPrefix  = "cilium_"
	ciliumNetNSPrefix = "cilium-"
	hostLinkPrefix    = "lxc"
	hostLinkLen       = len(hostLinkPrefix + "XXXXX")
	cniConfigV1       = "/etc/cni/net.d/10-cilium-cni.conf"
	cniConfigV2       = "/etc/cni/net.d/00-cilium-cni.conf"
	cniConfigV3       = "/etc/cni/net.d/05-cilium-cni.conf"
)

func init() {
	rootCmd.AddCommand(cleanupCmd)

	cleanupCmd.Flags().BoolVarP(&cleanAll, allFlagName, "", false, "Remove all cilium state")
	cleanupCmd.Flags().BoolVarP(&cleanBPF, bpfFlagName, "", false, "Remove BPF state")
	cleanupCmd.Flags().BoolVarP(&force, forceFlagName, "f", false, "Skip confirmation")

	option.BindEnv(allFlagName)
	option.BindEnv(bpfFlagName)

	bindEnv(cleanCiliumEnvVar, cleanCiliumEnvVar)
	bindEnv(cleanBpfEnvVar, cleanBpfEnvVar)

	if err := viper.BindPFlags(cleanupCmd.Flags()); err != nil {
		Fatalf("viper failed to bind to flags: %v\n", err)
	}
}

func bindEnv(flagName string, envName string) {
	if err := viper.BindEnv(flagName, envName); err != nil {
		Fatalf("Unable to bind flag %s to env variable %s: %s", flagName, envName, err)
	}
}

// cleanupFunc represents a function to cleanup specific state items.
type cleanupFunc func() error

// cleanup represents a set of cleanup actions.
type cleanup interface {
	// whatWillBeRemoved contains descriptions of
	// the removed state.
	whatWillBeRemoved() []string
	// cleanupFuncs contains a set of functions that
	// carry out cleanup actions.
	cleanupFuncs() []cleanupFunc
}

// bpfCleanup represents cleanup actions for BPF state.
type bpfCleanup struct{}

func (c bpfCleanup) whatWillBeRemoved() []string {
	return []string{
		fmt.Sprintf("all BPF maps in %s containing '%s' and '%s'",
			bpf.MapPrefixPath(), ciliumLinkPrefix, tunnel.MapName),
		fmt.Sprintf("mounted bpffs at %s", bpf.GetMapRoot()),
	}
}

func (c bpfCleanup) cleanupFuncs() []cleanupFunc {
	return []cleanupFunc{
		removeAllMaps,
	}
}

// ciliumCleanup represents cleanup actions for non-BPF state.
type ciliumCleanup struct {
	routes    map[int]netlink.Route
	links     map[int]netlink.Link
	tcFilters map[string][]*netlink.BpfFilter
	netNSs    []string
	bpfOnly   bool
}

func newCiliumCleanup(bpfOnly bool) ciliumCleanup {
	var routes map[int]netlink.Route
	var ciliumLinks map[int]netlink.Link
	var netNSs []string
	var err error

	if !bpfOnly {
		routes, ciliumLinks, err = findRoutesAndLinks()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		}

		netNSs, err = netns.ListNamedNetNSWithPrefix(ciliumNetNSPrefix)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		}
	}

	tcFilters := map[string][]*netlink.BpfFilter{}
	links, err := netlink.LinkList()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	} else {
		for _, link := range links {
			if filters, err := getTCFilters(link); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			} else if len(filters) != 0 {
				tcFilters[link.Attrs().Name] = filters
			}
		}
	}

	return ciliumCleanup{routes, ciliumLinks, tcFilters, netNSs, bpfOnly}
}

func (c ciliumCleanup) whatWillBeRemoved() []string {
	toBeRemoved := []string{}

	if len(c.tcFilters) > 0 {
		section := "tc filters\n"
		for linkName, f := range c.tcFilters {
			section += fmt.Sprintf("%s %v\n", linkName, f)
		}
		toBeRemoved = append(toBeRemoved, section)
	}

	if c.bpfOnly {
		return toBeRemoved
	}

	if len(c.routes) > 0 {
		section := "routes\n"
		for _, v := range c.routes {
			section += fmt.Sprintf("%v\n", v)
		}
		toBeRemoved = append(toBeRemoved, section)
	}

	if len(c.links) > 0 {
		section := "links\n"
		for _, v := range c.links {
			section += fmt.Sprintf("%v\n", v)
		}
		toBeRemoved = append(toBeRemoved, section)
	}

	if len(c.netNSs) > 0 {
		section := "network namespaces\n"
		for _, n := range c.netNSs {
			section += fmt.Sprintf("%s\n", n)
		}
		toBeRemoved = append(toBeRemoved, section)
	}

	toBeRemoved = append(toBeRemoved, fmt.Sprintf("mounted cgroupv2 at %s",
		defaults.DefaultCgroupRoot))
	toBeRemoved = append(toBeRemoved, fmt.Sprintf("library code in %s",
		defaults.LibraryPath))
	toBeRemoved = append(toBeRemoved, fmt.Sprintf("endpoint state in %s",
		defaults.RuntimePath))
	toBeRemoved = append(toBeRemoved, fmt.Sprintf("CNI configuration at %s, %s, %s",
		cniConfigV1, cniConfigV2, cniConfigV3))
	return toBeRemoved
}

func (c ciliumCleanup) cleanupFuncs() []cleanupFunc {
	cleanupRoutesAndLinks := func() error {
		return removeRoutesAndLinks(c.routes, c.links)
	}

	cleanupNamedNetNSs := func() error {
		return removeNamedNetNSs(c.netNSs)
	}

	cleanupTCFilters := func() error {
		return removeTCFilters(c.tcFilters)
	}

	funcs := []cleanupFunc{
		cleanupTCFilters,
	}
	if !c.bpfOnly {
		funcs = append(funcs, cleanupRoutesAndLinks)
		funcs = append(funcs, cleanupNamedNetNSs)
		funcs = append(funcs, unmountCgroup)
		funcs = append(funcs, removeDirs)
		funcs = append(funcs, removeCNI)
	}
	return funcs
}

func runCleanup() {
	// Abort if the agent is running, err == nil is handled correctly by Stat.
	if _, err := os.Stat(defaults.PidFilePath); !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Agent should not be running when cleaning up\n"+
			"Found pidfile %s\n", defaults.PidFilePath)
		os.Exit(1)
	}

	cleanAll = viper.GetBool(allFlagName) || viper.GetBool(cleanCiliumEnvVar)
	cleanBPF = viper.GetBool(bpfFlagName) || viper.GetBool(cleanBpfEnvVar)

	// if no flags are specifed then clean all
	if (cleanAll || cleanBPF) == false {
		cleanAll = true
	}

	var cleanups []cleanup

	// tc filter cleanup must come before removing files in BPF fs as
	// otherwise we remove tail call maps and get drops due to 'missed
	// tail call' in the datapath.
	cleanups = append(cleanups, newCiliumCleanup(!cleanAll && cleanBPF))
	if cleanAll || cleanBPF {
		cleanups = append(cleanups, bpfCleanup{})
	}
	if len(cleanups) == 0 {
		return
	}

	showWhatWillBeRemoved(cleanups)
	if !force && !confirmCleanup() {
		return
	}

	var cleanupFuncs []cleanupFunc
	for _, cleanup := range cleanups {
		cleanupFuncs = append(cleanupFuncs, cleanup.cleanupFuncs()...)
	}

	// ENOENT and similar errors are ignored. Should print all other
	// errors seen, but continue.  So that one remove function does not
	// prevent the remaining from running.
	for _, clean := range cleanupFuncs {
		if err := clean(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		}
	}
}

func showWhatWillBeRemoved(cleanups []cleanup) {
	var toBeRemoved []string

	for _, cleanup := range cleanups {
		toBeRemoved = append(toBeRemoved, cleanup.whatWillBeRemoved()...)
	}

	warning := "Warning: Destructive operation. You are about to remove:\n"
	for _, warn := range toBeRemoved {
		warning += fmt.Sprintf("- %s\n", warn)
	}

	fmt.Printf(warning)
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

func unmountCgroup() error {
	cgroupRoot := defaults.DefaultCgroupRoot
	cgroupRootStat, err := os.Stat(cgroupRoot)
	if err != nil {
		return nil
	} else if !cgroupRootStat.IsDir() {
		return fmt.Errorf("%s is a file which is not a directory", cgroupRoot)
	}

	log.Info("Trying to unmount ", cgroupRoot)
	if err := unix.Unmount(cgroupRoot, unix.MNT_FORCE); err != nil {
		return fmt.Errorf("Failed to unmount %s: %s", cgroupRoot, err)
	}
	return nil
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

func removeNamedNetNSs(netNSs []string) error {
	for _, n := range netNSs {
		if err := netns.RemoveNetNSWithName(n); err != nil {
			if strings.Contains(err.Error(), "No such file") {
				continue
			}
			return err
		}
		fmt.Printf("removed network namespace %s\n", n)
	}
	return nil
}

func getTCFilters(link netlink.Link) ([]*netlink.BpfFilter, error) {
	allFilters := []*netlink.BpfFilter{}

	for _, parent := range []uint32{tcFilterParentIngress, tcFilterParentEgress} {
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			return nil, err
		}
		for _, f := range filters {
			if bpfFilter, ok := f.(*netlink.BpfFilter); ok {
				if strings.Contains(bpfFilter.Name, "bpf_netdev") ||
					strings.Contains(bpfFilter.Name, "bpf_network") ||
					strings.Contains(bpfFilter.Name, "bpf_host") ||
					strings.Contains(bpfFilter.Name, "bpf_lxc") ||
					strings.Contains(bpfFilter.Name, "bpf_overlay") {
					allFilters = append(allFilters, bpfFilter)
				}
			}
		}
	}

	return allFilters, nil
}

func removeTCFilters(linkAndFilters map[string][]*netlink.BpfFilter) error {
	for name, filters := range linkAndFilters {
		for _, f := range filters {
			if err := netlink.FilterDel(f); err != nil {
				return err
			}
			fmt.Printf("removed tc filter %v of %s\n", f, name)
		}
	}

	return nil
}
