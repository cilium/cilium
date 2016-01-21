package daemon

import (
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/noironetworks/cilium-net/common/types"
)

func goArray2C(array []byte) string {
	ret := "{ "

	for i, e := range array {
		if i == 0 {
			ret = ret + fmt.Sprintf("%#x", e)
		} else {
			ret = ret + fmt.Sprintf(", %#x", e)
		}
	}

	return ret + " }"
}

func fmtDefineAddress(name string, addr []byte) string {
	return fmt.Sprintf("#define %s { .addr = %s }\n", name, goArray2C(addr))
}

func (d Daemon) EndpointJoin(ep types.Endpoint) error {

	lxcDir := "./" + ep.ID

	if err := os.MkdirAll(lxcDir, 0777); err != nil {
		log.Warningf("Failed to create container temporary directory: %s", err)
		return fmt.Errorf("Failed to create temporary directory: \"%s\"", err)
	}

	f, err := os.Create(lxcDir + "/lxc_config.h")
	if err != nil {
		os.RemoveAll(lxcDir)
		log.Warningf("Failed to create container headerfile: %s", err)
		return fmt.Errorf("Failed to create temporary directory: \"%s\"", err)

	}

	routerMac, _ := net.ParseMAC("de:ad:be:ef:c0:de")

	fmt.Fprintf(f, ""+
		"/*\n"+
		" * Container ID: %s\n"+
		" * MAC: %s\n"+
		" * IP: %s\n"+
		" * Router MAC: %s\n"+
		" * Router IP: %s\n"+
		" */\n\n",
		ep.ID, ep.LxcMAC.String(), ep.LxcIP.String(),
		ep.NodeIP.String(), routerMac.String())

	f.WriteString("#define DEBUG\n")
	f.WriteString("#define NODE_ID 1\n")
	f.WriteString(fmtDefineAddress("LXC_MAC", ep.LxcMAC))
	f.WriteString(fmtDefineAddress("LXC_IP", ep.LxcIP))
	f.WriteString(fmtDefineAddress("ROUTER_MAC", routerMac))
	f.WriteString(fmtDefineAddress("ROUTER_IP", ep.NodeIP))

	f.Close()

	args := []string{ep.ID, ep.Ifname, ep.LxcMAC.String(), ep.LxcIP.String()}
	out, err := exec.Command("../common/bpf/join_ep.sh", args...).CombinedOutput()
	if err != nil {
		log.Warningf("Command execution failed: %s", err)
		log.Warningf("Command output:\n%s", out)
		return fmt.Errorf("error: \"%s\"\noutput: \"%s\"", err, out)
	}
	log.Infof("Command successful:\n%s", out)

	return nil
}

func (d Daemon) EndpointLeave(epID string) error {
	lxcDir := "./" + epID
	os.RemoveAll(lxcDir)

	args := []string{epID}
	out, err := exec.Command("../common/bpf/leave_ep.sh", args...).CombinedOutput()
	if err != nil {
		log.Warningf("Command execution failed: %s", err)
		log.Warningf("Command output:\n%s", out)
		return fmt.Errorf("error: \"%s\"\noutput: \"%s\"", err, out)
	}
	log.Infof("Command successful:\n%s", out)

	return nil
}
