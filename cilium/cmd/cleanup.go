// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/socketlb"
)

// cleanupCmd represents the cleanup command
var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Remove system state installed by Cilium at runtime",
	Long: `Clean up CNI configurations, CNI binaries, attached BPF programs,
bpffs, tc filters, routes, links and named network namespaces.

Running this command might be necessary to get the worker node back into
working condition after uninstalling the Cilium agent.`,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cleanup")
		runCleanup()
	},
}

var (
	cleanAll bool
	cleanBPF bool
	force    bool
)

const (
	allFlagName   = "all-state"
	bpfFlagName   = "bpf-state"
	forceFlagName = "force"

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
	cniPath           = "/etc/cni/net.d"
	cniConfigV1       = cniPath + "/10-cilium-cni.conf"
	cniConfigV2       = cniPath + "/00-cilium-cni.conf"
	cniConfigV3       = cniPath + "/05-cilium-cni.conf"
	cniConfigV4       = cniPath + "/05-cilium.conf"
	cniConfigV5       = cniPath + "/05-cilium.conflist"
)

func init() {
	rootCmd.AddCommand(cleanupCmd)

	cleanupCmd.Flags().BoolVarP(&cleanAll, allFlagName, "", false, "Remove all cilium state")
	cleanupCmd.Flags().BoolVarP(&cleanBPF, bpfFlagName, "", false, "Remove BPF state")
	cleanupCmd.Flags().BoolVarP(&force, forceFlagName, "f", false, "Skip confirmation")

	option.BindEnv(vp, allFlagName)
	option.BindEnv(vp, bpfFlagName)

	bindEnv(cleanCiliumEnvVar, cleanCiliumEnvVar)
	bindEnv(cleanBpfEnvVar, cleanBpfEnvVar)

	if err := vp.BindPFlags(cleanupCmd.Flags()); err != nil {
		Fatalf("viper failed to bind to flags: %v\n", err)
	}
}

func bindEnv(flagName string, envName string) {
	if err := vp.BindEnv(flagName, envName); err != nil {
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
			bpf.TCGlobalsPath(), ciliumLinkPrefix, tunnel.MapName),
		fmt.Sprintf("mounted bpffs at %s", bpf.BPFFSRoot()),
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
	xdpLinks  []netlink.Link
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
	xdpLinks := []netlink.Link{}

	for _, link := range links {
		if ok, err := isCiliumXDPAttachedToLink(link); ok && err == nil {
			xdpLinks = append(xdpLinks, link)
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		}
	}

	return ciliumCleanup{routes, ciliumLinks, tcFilters, xdpLinks, netNSs, bpfOnly}
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
	if len(c.xdpLinks) > 0 {
		section := "xdp programs\n"
		for _, l := range c.xdpLinks {
			section += fmt.Sprintf("%s: xdp/prog id %v\n", l.Attrs().Name, l.Attrs().Xdp.ProgId)
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
	toBeRemoved = append(toBeRemoved, fmt.Sprintf("socketlb bpf programs at %s",
		defaults.DefaultCgroupRoot))
	toBeRemoved = append(toBeRemoved, fmt.Sprintf("mounted cgroupv2 at %s",
		defaults.DefaultCgroupRoot))
	toBeRemoved = append(toBeRemoved, fmt.Sprintf("library code in %s",
		defaults.LibraryPath))
	toBeRemoved = append(toBeRemoved, fmt.Sprintf("endpoint state in %s",
		defaults.RuntimePath))
	toBeRemoved = append(toBeRemoved, fmt.Sprintf("CNI configuration at %s, %s, %s, %s, %s",
		cniConfigV1, cniConfigV2, cniConfigV3, cniConfigV4, cniConfigV5))
	return toBeRemoved
}

func (c ciliumCleanup) cleanupFuncs() []cleanupFunc {
	cleanupRoutesAndLinks := func() error {
		return removeRoutesAndLinks(c.routes, c.links)
	}

	cleanupNamedNetNSs := func() error {
		return removeNamedNetNSs(c.netNSs)
	}
	cleanupXDPs := func() error {
		return removeXDPs(c.xdpLinks)
	}
	cleanupTCFilters := func() error {
		return removeTCFilters(c.tcFilters)
	}

	funcs := []cleanupFunc{
		cleanupTCFilters,
		cleanupXDPs,
		removeSocketLBPrograms,
	}
	if !c.bpfOnly {
		funcs = append(funcs, cleanupRoutesAndLinks)
		funcs = append(funcs, cleanupNamedNetNSs)
		funcs = append(funcs, unmountCgroup)
		funcs = append(funcs, removeDirs)
		funcs = append(funcs, revertCNIBackup)
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

	cleanAll = vp.GetBool(allFlagName) || vp.GetBool(cleanCiliumEnvVar)
	cleanBPF = vp.GetBool(bpfFlagName) || vp.GetBool(cleanBpfEnvVar)

	// if no flags are specified then clean all
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

	fmt.Print(warning)
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
	os.Remove(cniConfigV3)
	os.Remove(cniConfigV4)

	err := os.Remove(cniConfigV5)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// revertCNIBackup removes the ".cilium_bak" suffix from all files in cniPath,
// reverting them back to their original filenames.
func revertCNIBackup() error {
	return filepath.Walk(cniPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			if !strings.HasSuffix(path, ".cilium_bak") {
				return nil
			}
			origFileName := strings.TrimSuffix(path, ".cilium_bak")
			return os.Rename(path, origFileName)
		})
}

func removeSocketLBPrograms() error {
	if err := socketlb.Disable(); err != nil {
		return fmt.Errorf("Failed to detach all socketlb bpf programs from %s: %w", defaults.DefaultCgroupRoot, err)
	}
	fmt.Println("removed all socketlb bpf programs")
	return nil
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
	mapDir := bpf.TCGlobalsPath()
	maps, err := os.ReadDir(mapDir)
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
				// when blackhole route is encountered, the LinkIndex will get 0.
				if strings.Contains(err.Error(), "Link not found") || r.LinkIndex == 0 {
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
				// iproute2 uses the filename and section (bpf_overlay.o:[from-overlay])
				// as the filter name.
				if strings.Contains(bpfFilter.Name, "bpf_netdev") ||
					strings.Contains(bpfFilter.Name, "bpf_network") ||
					strings.Contains(bpfFilter.Name, "bpf_host") ||
					strings.Contains(bpfFilter.Name, "bpf_lxc") ||
					strings.Contains(bpfFilter.Name, "bpf_overlay") ||
					// Filters created by the Go bpf loader contain the bpf function and
					// interface name, like cil_from_netdev-eth0.
					strings.Contains(bpfFilter.Name, "cil_") {
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

func removeXDPs(links []netlink.Link) error {
	for _, link := range links {
		err := netlink.LinkSetXdpFdWithFlags(link, -1, int(nl.XDP_FLAGS_DRV_MODE))
		if err != nil {
			return err
		}
		err = netlink.LinkSetXdpFdWithFlags(link, -1, int(nl.XDP_FLAGS_SKB_MODE))
		if err != nil {
			return err
		}
		fmt.Printf("removed cilium xdp of %s\n", link.Attrs().Name)
	}
	return nil
}

func isCiliumXDPAttachedToLink(link netlink.Link) (bool, error) {
	linkxdp := link.Attrs().Xdp
	if linkxdp == nil || !linkxdp.Attached {
		return false, nil
	}

	ok, err := isCiliumXDP(linkxdp.ProgId)
	if ok && err == nil {
		return true, nil
	}

	return false, err
}

func isCiliumXDP(progId uint32) (bool, error) {
	xdp, err := ebpf.NewProgramFromID(ebpf.ProgramID(progId))
	if err != nil {
		return false, err
	}

	info, err := xdp.Info()
	if err != nil {
		return false, err
	}

	if strings.Contains(info.Name, "cil_xdp_entry") {
		return true, nil
	}

	return false, nil

}
