package bpfbackend

import (
	log "github.com/Sirupsen/logrus"
	ciliumtype "github.com/noironetworks/cilium-net/common/types"
	"os/exec"
)

func EndpointJoin(ep *ciliumtype.Endpoint) error {
	args := []string{ep.ID, ep.Ifname, ep.LxcMAC.String(), ep.LxcIP.String()}
	out, err := exec.Command("./join_ep.sh", args...).Output()
	if err != nil {
		log.Warnf("Command execution failed: %s", err)
		return err
	}
	log.Infof("Command successful:\n%s", out)

	return nil
}

func EndpointLeave(ep *ciliumtype.Endpoint) error {
	args := []string{ep.ID, ep.Ifname, ep.LxcMAC.String(), ep.LxcIP.String()}
	out, err := exec.Command("./leave_ep.sh", args...).Output()
	if err != nil {
		log.Warnf("Command execution failed: %s", err)
		return err
	}
	log.Infof("Command successful:\n%s", out)

	return nil
}
