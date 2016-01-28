package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"
)

var r, _ = regexp.Compile("^[0-9]+$")

func isValidID(id string) bool {
	return r.MatchString(id)
}

func (d Daemon) EndpointJoin(ep types.Endpoint) error {
	if !isValidID(ep.ID) {
		return fmt.Errorf("invalid ID %s", ep.ID)
	}
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

	fmt.Fprintf(f, ""+
		"/*\n"+
		" * Container ID: %s\n"+
		" * MAC: %s\n"+
		" * IP: %s\n"+
		" * Node MAC: %s\n"+
		" */\n\n",
		ep.ID, ep.LxcMAC.String(), ep.LxcIP.String(),
		ep.NodeMAC.String())

	f.WriteString(common.FmtDefineAddress("LXC_MAC", ep.LxcMAC))
	f.WriteString(common.FmtDefineAddress("LXC_IP", ep.LxcIP))
	f.WriteString(common.FmtDefineAddress("NODE_MAC", ep.NodeMAC))
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
	// Preventing someone from deleting important directories
	if !isValidID(epID) {
		return fmt.Errorf("invalid ID %s", epID)
	}
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
