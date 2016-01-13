package bpfbackend

import (
	"os/exec"

	ciliumtype "github.com/noironetworks/cilium-net/common/types"

	log "github.com/noironetworks/cilium-net/common/Godeps/_workspace/src/github.com/Sirupsen/logrus"
)

func EndpointJoin(ep *ciliumtype.Endpoint) error {
	args := []string{ep.ID, ep.Ifname, ep.LxcMAC.String(), ep.LxcIP.String()}
	out, err := exec.Command("./join_ep.sh", args...).CombinedOutput()
	if err != nil {
		log.Warnf("Command execution failed: %s", err)
		log.Warnf("Command output:\n%s", out)
		return err
	}
	log.Infof("Command successful:\n%s", out)

	return nil
}

func EndpointLeave(ep *ciliumtype.Endpoint) error {
	args := []string{ep.ID, ep.Ifname, ep.LxcMAC.String(), ep.LxcIP.String()}
	out, err := exec.Command("./leave_ep.sh", args...).CombinedOutput()
	if err != nil {
		log.Warnf("Command execution failed: %s", err)
		log.Warnf("Command output:\n%s", out)
		return err
	}
	log.Infof("Command successful:\n%s", out)

	return nil
}
