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
	encap_vxlan  = "cilium_vxlan"
	encap_geneve = "cilium_geneve"
	ENSTATE      = "/encap.state"
	DESTATE      = "/device.state"

	//FIXME; to refactor
	bpfoverlay  = "/var/lib/cilium/bpf/bpf_overlay.c"
	bpfoverlayo = "/var/lib/cilium/bpf_overlay.o"
	bpflb       = "/var/lib/cilium/bpf/bpf_lb.c"
	bpflbo      = "/var/lib/cilium/bpf_lb.o"
)

func bpfloader(args ...string) error {

	// make arguments readable
	stateDir := args[0]
	mode := args[1]

	var nativeDev string
	if len(args) == 3 {
		nativeDev = args[2]
	}

	// switch mode
	//FIXME: currently we cann't support vxlan and lb at the same time, I made it switch cases.
	switch mode {
	case "vxlan":
		{
			if err := loaderVxlan(); err != nil {
				return fmt.Errorf(" failed to load bpf program in vxlan mode %s", err)
			}
		}
	case "geneve":
		{
			if err := loaderGeneve(); err != nil {
				return fmt.Errorf(" failed to load bpf program in geneve mode %s", err)
			}

		}

	case "direct":
		{
			cmd := fmt.Sprintf("sysctl -w net.ipv6.conf.all.forwarding=1")
			execute(cmd, true, "")

			cmd = fmt.Sprintf("cilium identity get %s", WORLD_ID)
			id, err := execute(cmd, false, "")
			if err != nil {
				fmt.Errorf("Failed to get World ID %v", err)
				return err
			}

			opts := fmt.Sprintf("-DSECLABEL=%s -DPOLICY_MAP=cilium_policy_reserved_%s -DCALLS_MAP=cilium_calls_netdev_%s", id, id, id)
			if err = bpf_compile(nativeDev, opts, bpfnetdev, bpfnetdevo, "from-netdev"); err != nil {
				return fmt.Errorf("Failed to load nativeDev %v bpf program %v", nativeDev, err)
			}
			fpath := filepath.Join(stateDir, DESTATE)
			err = ioutil.WriteFile(fpath, []byte(nativeDev), 7550)
			if err != nil {
				return fmt.Errorf(" writing data to file %v failed, please check", fpath)
			}

		}
	case "lb":
		{
			cmd := fmt.Sprintf("sysctl -w net.ipv6.conf.all.forwarding=1")
			execute(cmd, true, "")

			hostId := fmt.Sprintf("cilium identity get %s", HOST_ID)
			identity, err := execute(hostId, false, "")
			if err != nil {
				return fmt.Errorf("failed to get host id using cilium cmd for %s, debug it manually", err)
			}

			opts := fmt.Sprintf("-DLB_L3 -DLB_L4 -DCALLS_MAP=cilium_calls_lb_%s", identity)
			if err = bpf_compile(nativeDev, opts, bpflb, bpflbo, "from-netdev"); err != nil {
				return fmt.Errorf("Failed to load nativeDev %v for lb bpf program %v", nativeDev, err)
			}
			fpath := filepath.Join(stateDir, DESTATE)
			err = ioutil.WriteFile(fpath, []byte(nativeDev), 7550)
			if err != nil {
				return fmt.Errorf(" writing data to file %v failed, please check", fpath)
			}

		}
	default:
		{
			fpath := filepath.Join(stateDir, ENSTATE)
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

func loaderVxlan() error {

	vxlan := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: encap_vxlan,
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

	vxiface, err := netlink.LinkByName(encap_vxlan)
	if err != nil {
		return fmt.Errorf("failed to get name %s caused for %v", encap_vxlan, err)
	}
	err = netlink.LinkSetUp(vxiface)
	if err != nil {
		return fmt.Errorf("vxlan dev failed to setup %v: %v", err)
	}

	vxindex := vxiface.Attrs().Index
	data := fmt.Sprintf("\n#define ENCAP_VXLAN 1\n#define ENCAP_IFINDEX %v", vxindex)

	fileName := filepath.Join(dir, NODE_CONFIG)
	f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_APPEND, 0666)
	defer f.Close()
	f.WriteString(data)

	//FIXME(Peiqi), need to optimize
	cmd := fmt.Sprintf("cilium identity get %s", WORLD_ID)
	id, err := execute(cmd, false, "")
	if err != nil {
		return fmt.Errorf("failed to get world_id identity: %s ", id)
	}
	intid, _ := strconv.Atoi(id)
	opts := fmt.Sprintf("-DSECLABEL=%v -DPOLICY_MAP=cilium_policy_reserved_%v -DCALLS_MAP=cilium_calls_overlay_%v", intid, intid, intid)
	if err = bpf_compile(encap_vxlan, opts, bpfoverlay, bpfoverlayo, "from-overlay"); err != nil {
		return fmt.Errorf("Failed to load vxlan bpf program %s", err)
	}

	// need to update the file content
	fpath := filepath.Join(dir, ENSTATE)
	if err = ioutil.WriteFile(fpath, []byte(encap_vxlan), 0666); err != nil {
		return fmt.Errorf(" writing data to file %v failed, please check", fpath)
	}

	return nil

}

func loaderGeneve() error {

	//Fixme: lib netlink not yet implements geneve type, temporary solution.
	var data string
	for _, item := range []loaderCommand{
		{fmt.Sprintf("ip link add %s type geneve external", encap_geneve), false, "Exist"},
		{fmt.Sprintf("ip link set %s up", encap_geneve), false, ""},
		{fmt.Sprintf("cat /sys/class/net/%s/ifindex", encap_geneve), false, ""},
	} {
		geindex, err := execute(item.cmd, item.ignoreAllErr, item.ignoreErrIfContains)
		if err != nil {
			fmt.Errorf("failed to set geneve dev in shell mode %s", err)
		}
		data = fmt.Sprintf("\n#define ENCAP_GENEVE 1\n#define ENCAP_IFINDEX %v", geindex)
	}

	// need to append in the file
	fileName := filepath.Join(dir, NODE_CONFIG)
	f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_APPEND, 0666)
	defer f.Close()
	f.WriteString(data)

	//FIXME(Peiqi), need to optimize
	cmd := fmt.Sprintf("cilium identity get %s", WORLD_ID)
	identity, err := execute(cmd, false, "")
	if err != nil {
		return fmt.Errorf("failed to get world_id identity: %s", identity)
	}
	opts := fmt.Sprintf("-DSECLABEL=%s -DPOLICY_MAP=cilium_policy_reserved_%s -DCALLS_MAP=cilium_calls_overlay_%s", identity, identity, identity)

	if err = bpf_compile(encap_geneve, opts, bpfoverlay, bpfoverlayo, "from-overlay"); err != nil {
		return fmt.Errorf("Failed to load geneve bpf program %s", err)
	}

	// need to update the file content
	fpath := filepath.Join(dir, ENSTATE)
	if err = ioutil.WriteFile(fpath, []byte(encap_geneve), 0666); err != nil {
		return fmt.Errorf(" writing data to file %v failed, please check", fpath)
	}
	return nil

}
