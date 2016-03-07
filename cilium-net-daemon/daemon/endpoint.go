package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"

	"github.com/noironetworks/cilium-net/bpf/policymap"
	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"
)

var r, _ = regexp.Compile("^[0-9]+$")

func isValidID(id string) bool {
	return r.MatchString(id)
}

func (d Daemon) insertEndpoint(dockerID string, ep *types.Endpoint) {
	d.endpointsMU.Lock()
	d.endpoints[dockerID] = ep
	d.endpointsMU.Unlock()
}

// Sets the given secLabel on the endpoint with the given dockerID. Returns true if the
// endpoint was found, false otherwise.
func (d Daemon) setEndpointSecLabel(dockerID string, secLabel uint32) bool {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	if ep, ok := d.endpoints[dockerID]; ok {
		ep.SecLabel = secLabel
		return true
	}
	return false
}

// Returns a copy of the endpoint for the given dockerID, or nil if the endpoint was not
// found.
func (d Daemon) getEndpoint(dockerID string) *types.Endpoint {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	if ep, ok := d.endpoints[dockerID]; ok {
		epCopy := *ep
		return &epCopy
	}
	return nil
}

func (d Daemon) deleteEndpoint(dockerID string) {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	delete(d.endpoints, dockerID)
}

func (d Daemon) EndpointJoin(ep types.Endpoint) error {
	if !isValidID(ep.ID) {
		return fmt.Errorf("invalid ID %s", ep.ID)
	}
	lxcDir := "./" + ep.ID
	policyMapPath := common.PolicyMapPath + ep.ID

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
		" * SecLabel: %#x\n"+
		" * PolicyMap: %s\n"+
		" */\n\n",
		ep.DockerID, ep.LxcMAC.String(), ep.LxcIP.String(), ep.SecLabel,
		path.Base(policyMapPath))

	f.WriteString(common.FmtDefineAddress("LXC_MAC", ep.LxcMAC))
	f.WriteString(common.FmtDefineAddress("LXC_IP", ep.LxcIP))
	fmt.Fprintf(f, "#define LXC_SECLABEL %#x\n", common.Swab32(ep.SecLabel))
	fmt.Fprintf(f, "#define LXC_POLICYMAP %s\n", path.Base(policyMapPath))

	f.WriteString("#define LXC_PORT_MAPPINGS ")
	for _, m := range ep.PortMap {
		// Write mappings directly in network byte order so we don't have
		// to convert it in the fast path
		fmt.Fprintf(f, "{%#x,%#x},", common.Swab16(m.From), common.Swab16(m.To))
	}
	f.WriteString("\n")

	f.Close()

	policyMap, err := policymap.OpenMap(policyMapPath)
	if err != nil {
		os.RemoveAll(lxcDir)
		log.Warningf("Could not create policy BPF map '%s': %s", policyMapPath, err)
		return fmt.Errorf("Could not create policy BPF map '%s': %s", policyMapPath, err)
	}

	ep.PolicyMap = policyMap
	if err := d.RegenerateConsumerMap(&ep); err != nil {
		os.RemoveAll(policyMapPath)
		os.RemoveAll(lxcDir)
		log.Warningf("Unable to generate policy map for '%s': %s", policyMapPath, err)
		return fmt.Errorf("Unable to generate policy map for '%s': %s", policyMapPath, err)
	}

	if err = d.lxcMap.WriteEndpoint(&ep); err != nil {
		os.RemoveAll(lxcDir)
		log.Warningf("Unable to update BPF map: %s", err)
		return fmt.Errorf("Unable to update eBPF map: %s", err)
	}

	args := []string{d.libDir, ep.ID, ep.Ifname}
	out, err := exec.Command(d.libDir+"/join_ep.sh", args...).CombinedOutput()
	if err != nil {
		os.RemoveAll(lxcDir)
		log.Warningf("Command execution failed: %s", err)
		log.Warningf("Command output:\n%s", out)
		return fmt.Errorf("error: \"%s\"\noutput: \"%s\"", err, out)
	}
	d.insertEndpoint(ep.DockerID, &ep)
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

	if err := d.lxcMap.DeleteElement(epID); err != nil {
		log.Warningf("Unable to remove endpoint from map: %s", err)
	}

	args := []string{d.libDir, epID}
	out, err := exec.Command(d.libDir+"/leave_ep.sh", args...).CombinedOutput()
	if err != nil {
		log.Warningf("Command execution failed: %s", err)
		log.Warningf("Command output:\n%s", out)
		return fmt.Errorf("error: \"%s\"\noutput: \"%s\"", err, out)
	}

	// Clear policy map
	os.RemoveAll(common.PolicyMapPath + epID)

	// TODO: We need to retrieve docker container ID to perform map endpoint delete
	log.Infof("Command successful:\n%s", out)

	return nil
}
