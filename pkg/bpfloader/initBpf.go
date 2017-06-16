package bpfloader

import (
	"context"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	HOST_ID     = "host"
	WORLD_ID    = "world"
	HOST_DEV    = "cilium_host"
	NET_DEV     = "cilium_net"
	NODE_CONFIG = "/globals/node_config.h"

	// ExecTimeout is the execution timeout to use in run_probes.sh executions
	ExecTimeout = time.Duration(30 * time.Second)

	//FIXME: to refactor
	dir        = "/var/run/cilium/state"
	bpfnetdev  = "/var/lib/cilium/bpf/bpf_netdev.c"
	bpfnetdevo = "/var/lib/cilium/bpf_netdev.o"
	libbpf     = "/var/lib/cilium/bpf"
)

func bpf_compile(dev, opts, in, out, section string) error {

	iface, err := netlink.LinkByName(dev)
	if err != nil {
		return fmt.Errorf("failed to get interface index for %s, %v ", dev, err)
	}

	//mac2array
	node_mac := iface.Attrs().HardwareAddr
	macarray := fmt.Sprintf("0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x", node_mac[0], node_mac[1], node_mac[2], node_mac[3], node_mac[4], node_mac[5])
	macarray = fmt.Sprintf("{.addr={%v}}", macarray)

	nproc := runtime.NumCPU()
	clang_opts := fmt.Sprintf("-D__NR_CPUS__=%v -O2 -target bpf -I%s -I%s/globals -I%s/include -DENABLE_ARP_RESPONDER -DHANDLE_NS -Wunknown-warning-option -Wunknown-warning-option", nproc, dir, dir, libbpf)
	for _, item := range []loaderCommand{
		{fmt.Sprintf("clang %s %s -DNODE_MAC=%s -c %s -o %s", clang_opts, opts, macarray, in, out), false, ""},
		{fmt.Sprintf("tc qdisc del dev %s clsact", dev), true, ""},
		{fmt.Sprintf("tc qdisc add dev %s clsact", dev), false, ""},
		{fmt.Sprintf("tc filter add dev %s ingress prio 1 handle 1 bpf da obj %s sec %s", dev, out, section), false, ""},
	} {
		if _, err := execute(item.cmd, item.ignoreAllErr, item.ignoreErrIfContains); err != nil {
			fmt.Printf("clang %s %s -DNODE_MAC=%s -c %s -o %s", clang_opts, opts, macarray, in, out)
			return fmt.Errorf("Failed occurred during load BPF program: %s, please check! ", err)
		}
	}
	return nil
}

func InitBPF(args ...string) error {

	//Fixme, to make more readable and propre
	bpfDir := args[0]
	stateDir := args[1]
	nodeAddr := args[2]
	ipv4Addr := args[3]
	mode := args[4]

	var nativeDev string
	if len(args) == 6 {
		nativeDev = args[5]
	}

	//FIXME: to change run_probes.sh script in golang or C implementation.
	//at the beginning, execute run_probes script.
	prog := filepath.Join(bpfDir, "run_probes.sh")
	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, prog, bpfDir, stateDir).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		log.Errorf("Command execution failed: Timeout for %s %s %s", prog, bpfDir, stateDir)
		return fmt.Errorf("Command execution failed: Timeout for %s %s %s", prog, bpfDir, stateDir)
	}
	if err != nil {
		log.Warningf("Command execution %s %s failed: %s", prog,
			strings.Join(args, " "), err)
		log.Warningf("Command output:\n%s", out)
		return err
	}

	for _, item := range []loaderCommand{
		{fmt.Sprintf("command -V cilium"), false, ""},
		{fmt.Sprintf("sysctl -w net.core.bpf_jit_enable=1"), true, ""},
		{fmt.Sprintf("sysctl -w net.ipv4.conf.all.rp_filter=0"), true, ""},
		{fmt.Sprintf("sysctl -w net.ipv6.conf.all.disable_ipv6=0"), true, ""},
	} {
		if _, err := execute(item.cmd, item.ignoreAllErr, item.ignoreErrIfContains); err != nil {
			return err
		}
	}

	// create cilium host net veth pair
	if err = cilium_veth_pair(nodeAddr, ipv4Addr); err != nil {
		return fmt.Errorf(" failed to create cilium veth pair: %s ", err)
	}

	// bpf program load
	if mode == "vxlan" || mode == "geneve" {
		if err := bpfloader(stateDir, mode); err != nil {
			return fmt.Errorf(" failed to load bpf program to vxlan dev %v ", err)
		}
	} else {
		if err := bpfloader(stateDir, mode, nativeDev); err != nil {
			return fmt.Errorf(" failed to load bpf program to nativ dev %v ", err)
		}
	}

	return nil
}

func cilium_veth_pair(nodeAddr, ipv4Addr string) error {

	// setup cilium_host cilium_net device.
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: HOST_DEV},
		PeerName:  NET_DEV,
	}

	//FIXME: make check before delete instead of direct deletion
	if err := netlink.LinkDel(veth); err != nil {
		log.Debug("warnning, unable to delete veth pair %v, cause by %v", veth, err)
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("unable to create cilium host net veth pair: %s ", err)
	}

	log.Debugf("Created veth pair %s <-> %s", HOST_DEV, NET_DEV)

	hiface, err := netlink.LinkByName(HOST_DEV)
	if err != nil {
		return fmt.Errorf("failed to get cilium host device %s ", err)
	}
	err = netlink.LinkSetUp(hiface)
	if err != nil {
		return fmt.Errorf("failed to setup veth pair %v, %s ", hiface, err)
	}
	err = netlink.LinkSetARPOff(hiface)
	if err != nil {
		log.Debug("Warnning, disable flood mode failed for veth pair %v ", hiface)
	}

	niface, err := netlink.LinkByName(NET_DEV)
	if err != nil {
		return fmt.Errorf("failed to get cilium net device %v", err)
	}
	err = netlink.LinkSetUp(niface)
	if err != nil {
		return fmt.Errorf("failed to setup veth pair %v, %s", niface, err)
	}
	err = netlink.LinkSetARPOff(niface)
	if err != nil {
		log.Debug("Warnning, disable flood mode failed for veth pair %v ", niface)
	}

	// for route config
	nindex := niface.Attrs().Index
	//mac2array
	hostmac := hiface.Attrs().HardwareAddr
	hostarray := fmt.Sprintf("0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x", hostmac[0], hostmac[1], hostmac[2], hostmac[3], hostmac[4], hostmac[5])
	hostarray = fmt.Sprintf("{ .addr = {%v}}", hostarray)

	//write to runtime file
	data := fmt.Sprintf("#define HOST_IFINDEX %v \n#define HOST_IFINDEX_MAC %s", nindex, hostarray)
	fpath := filepath.Join(dir, NODE_CONFIG)
	f, err := os.OpenFile(fpath, os.O_WRONLY|os.O_APPEND, 0666)
	f.WriteString(data)

	//FIXME(Peiqi), need to optimize
	hostId := fmt.Sprintf("cilium identity get %s", HOST_ID)
	id, err := execute(hostId, false, "")
	if err != nil {
		return fmt.Errorf("failed to get identity %s, %v", hostId, err)
	}
	intid, _ := strconv.Atoi(id)
	opts := fmt.Sprintf("-DFIXED_SRC_SECCTX=%v -DSECLABEL=%v -DPOLICY_MAP=cilium_policy_reserved_%v -DCALLS_MAP=cilium_calls_netdev_ns_%v", intid, intid, intid, intid)
	if err = bpf_compile(NET_DEV, opts, bpfnetdev, bpfnetdevo, "from-netdev"); err != nil {
		return fmt.Errorf("Failed to load cilium_net bpf program %s", err)
	}

	//FIXME(Peiqi) optimize ipv6 traitement
	nipv6 := strings.TrimSuffix(nodeAddr, ":0")
	hipv6 := nipv6 + ":ffff"
	ipv6 := net.ParseIP(hipv6)       //cilium host ip
	netipv6 := net.ParseIP(nodeAddr) //cilium net

	ipn := new(net.IPNet)
	ipn.Mask = net.CIDRMask(128, 128)
	ipn.IP = ipv6
	addr := netlink.Addr{IPNet: ipn}
	err = netlink.AddrDel(hiface, &addr)
	if err != nil {
		log.Debug("failed to delete cilium host addr %s", err)
	}
	err = netlink.AddrAdd(hiface, &addr)
	if err != nil {
		return fmt.Errorf("Add cilium host ip address failed due to %s", err)
	}

	ipn.IP = netipv6
	route1 := netlink.Route{ // route1 is route for cilium host
		Dst:       ipn,
		LinkIndex: hiface.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
	}
	//FIXME: to make more robust
	err = netlink.RouteDel(&route1)
	if err != nil {
		fmt.Printf(" failed to delete route before add it, %v ", err)
	}

	if err = netlink.RouteAdd(&route1); err != nil {
		return fmt.Errorf("ipv6 route add for cilium host failed: %v", err)
	}
	ipn.Mask = net.CIDRMask(96, 128)
	route2 := netlink.Route{
		Dst:       ipn,
		LinkIndex: hiface.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Gw:        netipv6,
	}

	//Check if route2 exists before attempting to add it
	routeList, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Dst: route2.Dst}, netlink.RT_FILTER_DST)
	if err != nil {
		log.Debugf("Failed to list routes: %v", err)
	}
	// FIXME: to make more robust
	if len(routeList) > 0 && !routeList[0].Gw.Equal(route2.Gw) {
		err = netlink.RouteDel(&route2)
		if err != nil {
			fmt.Printf(" failed to delete route before add it, %v ", err)
		}
	}
	if err = netlink.RouteAdd(&route2); err != nil {
		fmt.Errorf("ipv6 route add failed: %s", err)
	}

	//route config for ipv4
	// FIXME ME, to optimize
	str2array := strings.Split(ipv4Addr, ".")
	stripv4 := str2array[0] + "." + str2array[1] + ".0.1"
	ipv4 := net.ParseIP(stripv4) // ipv4 of cilium host

	ipn4 := new(net.IPNet)
	ipn4.IP = ipv4
	ipn4.Mask = net.CIDRMask(32, 32)
	addrv4 := netlink.Addr{IPNet: ipn4}

	err = netlink.AddrDel(hiface, &addrv4)
	if err != nil {
		log.Debug(" failed to delete addr before add it, %v ", err)
	}
	err = netlink.AddrAdd(hiface, &addrv4)
	if err != nil {
		return fmt.Errorf(" Failed to add ipv4 addr: %v ", err)
	}

	route1 = netlink.Route{
		Dst:       ipn4,
		LinkIndex: hiface.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
	}
	//FIXME: to make robust
	err = netlink.RouteDel(&route1)
	if err != nil {
		log.Debug(" failed to delete route before add it %v ", err)
	}

	err = netlink.RouteAdd(&route1)
	if err != nil {
		return fmt.Errorf(" failed to add ipv4 route for cilium host %v ", err)
	}

	//FIXME: to optimize ip traitement
	nstripv4 := str2array[0] + "." + str2array[1] + ".0.0"
	nipv4 := net.ParseIP(nstripv4)
	ipn4.IP = nipv4
	ipn4.Mask = net.CIDRMask(16, 32) //ip for cilium net
	route2 = netlink.Route{
		Dst:       ipn4,
		LinkIndex: hiface.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Gw:        ipv4,
	}

	//FIXME: to check before delete instead of direct make a route deletion
	err = netlink.RouteDel(&route2)
	if err != nil {
		log.Debug(" failed to delete route before setup: %s ", err)
	}
	err = netlink.RouteAdd(&route2)
	if err != nil {
		return fmt.Errorf(" Failed to add ipv4 route %v ", err)
	}

	return nil
}
