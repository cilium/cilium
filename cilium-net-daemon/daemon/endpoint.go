package daemon

import (
	"fmt"
	"os/exec"

	"github.com/noironetworks/cilium-net/common/types"
)

func (d Daemon) EndpointJoin(ep types.Endpoint) error {
	args := []string{ep.ID, ep.Ifname, ep.LxcMAC.String(), ep.LxcIP.String()}
	out, err := exec.Command("../../common/bpf/join_ep.sh", args...).CombinedOutput()
	if err != nil {
		log.Warningf("Command execution failed: %s", err)
		log.Warningf("Command output:\n%s", out)
		return fmt.Errorf("error: \"%s\"\noutput: \"%s\"", err, out)
	}
	log.Infof("Command successful:\n%s", out)

	return nil
}

func (d Daemon) EndpointLeave(epID string) error {
	args := []string{epID}
	out, err := exec.Command("../../common/bpf/leave_ep.sh", args...).CombinedOutput()
	if err != nil {
		log.Warningf("Command execution failed: %s", err)
		log.Warningf("Command output:\n%s", out)
		return fmt.Errorf("error: \"%s\"\noutput: \"%s\"", err, out)
	}
	log.Infof("Command successful:\n%s", out)

	return nil
}
