package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"

	"github.com/noironetworks/cilium-net/bpf/policymap"
	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"
)

var r, _ = regexp.Compile("^[0-9]+$")

func isValidID(id string) bool {
	return r.MatchString(id)
}

func (d *Daemon) insertEndpoint(ep *types.Endpoint) {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	d.endpoints[types.CiliumPreffix+ep.ID] = ep
	if ep.DockerID != "" {
		d.endpoints[types.DockerPreffix+ep.DockerID] = ep
	}
}

// Sets the given secLabel on the endpoint with the given endpointID. Returns a pointer of
// a copy endpoint if the endpoint was found, nil otherwise.
func (d *Daemon) setEndpointSecLabel(endpointID, dockerID string, secLabel uint32) *types.Endpoint {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	if endpointID != "" {
		if ep, ok := d.endpoints[types.CiliumPreffix+endpointID]; ok {
			ep.SecLabel = secLabel
			epCopy := *ep
			return &epCopy
		}
	} else if dockerID != "" {
		if ep, ok := d.endpoints[types.DockerPreffix+dockerID]; ok {
			ep.SecLabel = secLabel
			epCopy := *ep
			return &epCopy
		}
	}
	return nil
}

// Returns a copy of the endpoint for the given endpointID, or nil if the endpoint was not
// found.
func (d *Daemon) getEndpoint(endpointID string) *types.Endpoint {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	if ep, ok := d.endpoints[types.CiliumPreffix+endpointID]; ok {
		epCopy := *ep
		return &epCopy
	}
	return nil
}

func (d *Daemon) deleteEndpoint(endpointID string) {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	if ep, ok := d.endpoints[types.CiliumPreffix+endpointID]; ok {
		delete(d.endpoints, types.DockerPreffix+ep.DockerID)
		delete(d.endpoints, types.CiliumPreffix+endpointID)
	}
}

func (d *Daemon) createBPF(r_ep types.Endpoint) error {
	if !isValidID(r_ep.ID) {
		return fmt.Errorf("invalid ID %s", r_ep.ID)
	}

	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	ep, ok := d.endpoints[types.CiliumPreffix+r_ep.ID]
	if !ok {
		log.Warningf("Unable to find endpoint\n")
		return fmt.Errorf("Unable to find endpoint\n")
	}

	lxcDir := filepath.Join(".", ep.ID)
	f, err := os.Create(filepath.Join(lxcDir, "lxc_config.h"))
	if err != nil {
		os.RemoveAll(lxcDir)
		log.Warningf("Failed to create container headerfile: %s", err)
		return fmt.Errorf("Failed to create temporary directory: \"%s\"", err)

	}

	fmt.Fprint(f, "/*\n")
	if ep.DockerID == "" {
		fmt.Fprintf(f, " * Docker Network ID: %s\n", ep.DockerNetwork)
	} else {
		fmt.Fprintf(f, " * Docker Container ID: %s\n", ep.DockerID)
	}
	policyMapPath := common.PolicyMapPath + ep.ID

	fmt.Fprintf(f, " * MAC: %s\n"+
		" * IP: %s\n"+
		" * SecLabel: %#x\n"+
		" * PolicyMap: %s\n"+
		" * NodeMAC: %s\n"+
		" */\n\n",
		ep.LxcMAC.String(), ep.LxcIP.String(), ep.SecLabel,
		path.Base(policyMapPath), ep.NodeMAC.String())

	labels, err := d.GetLabels(int(ep.SecLabel))
	if err != nil {
		return err
	}

	f.WriteString("/*\n")
	f.WriteString(" * Labels:\n")
	for k, v := range *labels {
		fmt.Fprintf(f, " * - %s=%s\n", k, v)
	}
	f.WriteString(" */\n\n")

	f.WriteString(common.FmtDefineAddress("LXC_MAC", ep.LxcMAC))
	f.WriteString(common.FmtDefineAddress("LXC_IP", ep.LxcIP))
	fmt.Fprintf(f, "#define LXC_SECLABEL_NB %#x\n", common.Swab32(ep.SecLabel))
	fmt.Fprintf(f, "#define LXC_SECLABEL %#x\n", ep.SecLabel)
	fmt.Fprintf(f, "#define LXC_POLICY_MAP %s\n", path.Base(policyMapPath))
	f.WriteString(common.FmtDefineAddress("NODE_MAC", ep.NodeMAC))

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
	if err := d.RegenerateConsumerMap(ep); err != nil {
		os.RemoveAll(policyMapPath)
		os.RemoveAll(lxcDir)
		log.Warningf("Unable to generate policy map for '%s': %s", policyMapPath, err)
		return fmt.Errorf("Unable to generate policy map for '%s': %s", policyMapPath, err)
	}

	if err = d.lxcMap.WriteEndpoint(ep); err != nil {
		os.RemoveAll(lxcDir)
		log.Warningf("Unable to update BPF map: %s", err)
		return fmt.Errorf("Unable to update eBPF map: %s", err)
	}

	args := []string{d.libDir, ep.ID, ep.Ifname}
	out, err := exec.Command(filepath.Join(d.libDir, "join_ep.sh"), args...).CombinedOutput()
	if err != nil {
		os.RemoveAll(lxcDir)
		log.Warningf("Command execution failed: %s", err)
		log.Warningf("Command output:\n%s", out)
		return fmt.Errorf("error: \"%s\"\noutput: \"%s\"", err, out)
	}
	log.Infof("Command successful:\n%s", out)
	return nil
}

func (d *Daemon) EndpointJoin(ep types.Endpoint) error {
	if !isValidID(ep.ID) {
		return fmt.Errorf("invalid ID %s", ep.ID)
	}
	lxcDir := filepath.Join(".", ep.ID)

	if err := os.MkdirAll(lxcDir, 0777); err != nil {
		log.Warningf("Failed to create container temporary directory: %s", err)
		return fmt.Errorf("Failed to create temporary directory: \"%s\"", err)
	}

	d.insertEndpoint(&ep)

	return nil
}

func (d *Daemon) EndpointLeave(epID string) error {
	// Preventing someone from deleting important directories
	if !isValidID(epID) {
		return fmt.Errorf("invalid ID %s", epID)
	}
	lxcDir := filepath.Join(".", epID)
	os.RemoveAll(lxcDir)

	if err := d.lxcMap.DeleteElement(epID); err != nil {
		log.Warningf("Unable to remove endpoint from map: %s", err)
	}

	args := []string{d.libDir, epID}
	out, err := exec.Command(filepath.Join(d.libDir, "leave_ep.sh"), args...).CombinedOutput()
	if err != nil {
		log.Warningf("Command execution failed: %s", err)
		log.Warningf("Command output:\n%s", out)
		return fmt.Errorf("error: \"%s\"\noutput: \"%s\"", err, out)
	}

	// Clear policy map
	os.RemoveAll(common.PolicyMapPath + epID)

	d.deleteEndpoint(epID)

	log.Infof("Command successful:\n%s", out)

	return nil
}
