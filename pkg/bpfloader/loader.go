package bpfloader

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
)

const (
	encapVxlan  = "cilium_vxlan"
	encapGeneve = "cilium_geneve"
	enState      = "/encap.state"
	devState      = "/device.state"
	bpfOverlay  = "bpf_overlay.c"
	bpfOverlayo = "bpf_overlay.o"
	bpfLb       = "bpf/bpf_lb.c"
	bpfLbo      = "bpf_lb.o"
)

func bpfloader(args ...string) error {

	// make arguments readable
	stateDir := args[0]
	bpfDir := args[1]
	mode := args[2]


	var nativeDev string
	if len(args) == 4 {
		nativeDev = args[2]
	}

	// switch mode
	//FIXME: currently we cann't support vxlan and lb at the same time, I made it switch cases.
	switch mode {
	case "vxlan":
		{
			if err := loaderVxlan(stateDir, bpfDir); err != nil {
				return fmt.Errorf("failed to load bpf program in vxlan mode %s", err)
			}
		}
	case "geneve":
		{
			if err := loaderGeneve(stateDir, bpfDir); err != nil {
				return fmt.Errorf("failed to load bpf program in geneve mode %s", err)
			}

		}

	case "direct":
		{
			cmd := fmt.Sprintf("sysctl -w net.ipv6.conf.all.forwarding=1")
			execute(cmd, true, "")

			cmd = fmt.Sprintf("cilium identity get %s", worldID)
			id, err := execute(cmd, false, "")
			if err != nil {
				fmt.Errorf("Failed to get World ID %v", err)
				return err
			}

			opts := fmt.Sprintf("-DSECLABEL=%s -DPOLICY_MAP=cilium_policy_reserved_%s -DCALLS_MAP=cilium_calls_netdev_%s", id, id, id)
			if err = bpfCompile(nativeDev, opts, bpfNetdev, bpfNetdevo, "from-netdev", stateDir, bpfDir); err != nil {
				return fmt.Errorf("Failed to load nativeDev %v bpf program %v", nativeDev, err)
			}
			fpath := filepath.Join(stateDir, devState)
			err = ioutil.WriteFile(fpath, []byte(nativeDev), 7550)
			if err != nil {
				return fmt.Errorf(" writing data to file %v failed, please check", fpath)
			}

		}
	case "lb":
		{
			cmd := fmt.Sprintf("sysctl -w net.ipv6.conf.all.forwarding=1")
			execute(cmd, true, "")

			hostID := fmt.Sprintf("cilium identity get %s", hostID)
			identity, err := execute(hostID, false, "")
			if err != nil {
				return fmt.Errorf("failed to get host id using cilium cmd for %s, debug it manually", err)
			}

			opts := fmt.Sprintf("-DLB_L3 -DLB_L4 -DCALLS_MAP=cilium_calls_lb_%s", identity)
			if err = bpfCompile(nativeDev, opts, bpfLb, bpfLbo, "from-netdev", stateDir, bpfDir); err != nil {
				return fmt.Errorf("Failed to load nativeDev %v for lb bpf program %v", nativeDev, err)
			}
			fpath := filepath.Join(stateDir, devState)
			err = ioutil.WriteFile(fpath, []byte(nativeDev), 7550)
			if err != nil {
				return fmt.Errorf("writing data to file %v failed, please check", fpath)
			}

		}
	default:
		{
			fpath := filepath.Join(stateDir, enState)
			data, err := ioutil.ReadFile(fpath)
			if err != nil {
				fmt.Errorf("Failed to read device from file：%s, for %v", fpath, data)
			}
			cmd := fmt.Sprintf("tc qdisc del dev %s clsact", string(data))
			execute(cmd, true, "")
			return nil
		}
	}

	return nil
}

func loaderVxlan(stateDir, bpfDir string) error {

	vxlan := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: encapVxlan,
		},
		Learning:  false,
		FlowBased: true,
	}

	err := netlink.LinkDel(vxlan)
	if err != nil {
		log.Debug("Delete vxlan dev failed: %s", err)
	}
	if err = netlink.LinkAdd(vxlan); err != nil {
		return fmt.Errorf("vxlan dev add failed: %v", err)
	}

	vxiface, err := netlink.LinkByName(encapVxlan)
	if err != nil {
		return fmt.Errorf("failed to get name %s caused for %v", encapVxlan, err)
	}
	err = netlink.LinkSetUp(vxiface)
	if err != nil {
		return fmt.Errorf("vxlan dev failed to setup %v: %v", err)
	}

	vxindex := vxiface.Attrs().Index
	data := fmt.Sprintf("\n#define encapVxlan 1\n#define ENCAP_IFINDEX %v", vxindex)

	fileName := filepath.Join(stateDir, nodeConfig)
	f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_APPEND, 0644)
	defer f.Close()
	_, err = f.WriteString(data)
	if err != nil {
		fmt.Errorf("failed to write data %v to file %v", data, f)
	}

	//FIXME, need to optimize
	cmd := fmt.Sprintf("cilium identity get %s", worldID)
	id, err := execute(cmd, false, "")
	if err != nil {
		return fmt.Errorf("failed to get world_id identity: %s", id)
	}
	intid, _ := strconv.Atoi(id)
	opts := fmt.Sprintf("-DSECLABEL=%v -DPOLICY_MAP=cilium_policy_reserved_%v -DCALLS_MAP=cilium_calls_overlay_%v", intid, intid, intid)
	if err = bpfCompile(encapVxlan, opts, bpfOverlay, bpfOverlayo, "from-overlay", stateDir, bpfDir); err != nil {
		return fmt.Errorf("Failed to load vxlan bpf program %s", err)
	}

	// need to update the file content
	fpath := filepath.Join(stateDir, enState)
	if err = ioutil.WriteFile(fpath, []byte(encapVxlan), 0644); err != nil {
		return fmt.Errorf("writing data to file %v failed, please check", fpath)
	}

	return nil

}

func loaderGeneve(stateDir, bpfDir string) error {

	//Fixme: lib netlink not yet implements geneve type, temporary solution.
	var data string
	for _, item := range []loaderCommand{
		{fmt.Sprintf("ip link add %s type geneve external", encapGeneve), false, "Exist"},
		{fmt.Sprintf("ip link set %s up", encapGeneve), false, ""},
		{fmt.Sprintf("cat /sys/class/net/%s/ifindex", encapGeneve), false, ""},
	} {
		geindex, err := execute(item.cmd, item.ignoreAllErr, item.ignoreErrIfContains)
		if err != nil {
			fmt.Errorf("failed to set geneve dev in shell mode %s", err)
		}
		data = fmt.Sprintf("\n#define encapGeneve 1\n#define ENCAP_IFINDEX %v", geindex)
	}

	// need to append in the file
	fileName := filepath.Join(stateDir, nodeConfig)
	f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_APPEND, 0644)
	defer f.Close()
	_, err = f.WriteString(data)
	if err != nil {
		fmt.Errorf("failed to write data %v to file %v", data, f)
	}

	//FIXME, write in C ??
	cmd := fmt.Sprintf("cilium identity get %s", worldID)
	identity, err := execute(cmd, false, "")
	if err != nil {
		return fmt.Errorf("failed to get world_id identity: %s", identity)
	}
	opts := fmt.Sprintf("-DSECLABEL=%s -DPOLICY_MAP=cilium_policy_reserved_%s -DCALLS_MAP=cilium_calls_overlay_%s", identity, identity, identity)

	if err = bpfCompile(encapGeneve, opts, bpfOverlay, bpfOverlayo, "from-overlay", stateDir, bpfDir); err != nil {
		return fmt.Errorf("Failed to load geneve bpf program %s", err)
	}

	// need to update the file content
	fpath := filepath.Join(stateDir, enState)
	if err = ioutil.WriteFile(fpath, []byte(encapGeneve), 0644); err != nil {
		return fmt.Errorf("writing data to file %v failed, please check", fpath)
	}
	return nil

}
