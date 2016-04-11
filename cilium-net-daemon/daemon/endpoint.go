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
	d.endpoints[common.CiliumPrefix+ep.ID] = ep
	if ep.DockerID != "" {
		d.endpoints[common.DockerPrefix+ep.DockerID] = ep
	}
}

// Sets the given secLabel on the endpoint with the given endpointID. Returns a pointer of
// a copy endpoint if the endpoint was found, nil otherwise.
func (d *Daemon) setEndpointSecLabel(endpointID, dockerID string, labels *types.SecCtxLabel) *types.Endpoint {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	id := ""
	if endpointID != "" {
		id = common.CiliumPrefix + endpointID
	} else if dockerID != "" {
		id = common.DockerPrefix + dockerID
	} else {
		return nil
	}

	if ep, ok := d.endpoints[id]; ok {
		ep.SetSecLabel(labels)
		epCopy := *ep
		return &epCopy
	}

	return nil
}

// Returns a copy of the endpoint for the given endpointID, or nil if the endpoint was not
// found.
func (d *Daemon) getEndpoint(endpointID string) *types.Endpoint {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	if ep, ok := d.endpoints[common.CiliumPrefix+endpointID]; ok {
		epCopy := *ep
		return &epCopy
	}
	return nil
}

func (d *Daemon) deleteEndpoint(endpointID string) {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	if ep, ok := d.endpoints[common.CiliumPrefix+endpointID]; ok {
		delete(d.endpoints, common.DockerPrefix+ep.DockerID)
		delete(d.endpoints, common.CiliumPrefix+endpointID)
	}
}

func (d *Daemon) createBPF(rEP types.Endpoint) error {
	if !isValidID(rEP.ID) {
		return fmt.Errorf("invalid ID %s", rEP.ID)
	}

	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	ep, ok := d.endpoints[common.CiliumPrefix+rEP.ID]
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
		" * IPv6 address: %s\n"+
		" * IPv4 address: %s\n"+
		" * SecLabel: %#x\n"+
		" * PolicyMap: %s\n"+
		" * NodeMAC: %s\n"+
		" */\n\n",
		ep.LXCMAC.String(), ep.LXCIP.String(),
		ep.IPv4Address(d.ipv4Range).String(), ep.SecLabelID,
		path.Base(policyMapPath), ep.NodeMAC.String())

	secCtxlabels, err := d.GetLabels(int(ep.SecLabelID))
	if err != nil {
		return err
	}

	f.WriteString("/*\n")
	f.WriteString(" * Labels:\n")
	for k, v := range secCtxlabels.Labels {
		fmt.Fprintf(f, " * - %s=%s\n", k, v)
	}
	f.WriteString(" */\n\n")

	f.WriteString(common.FmtDefineAddress("LXC_MAC", ep.LXCMAC))
	f.WriteString(common.FmtDefineAddress("LXC_IP", ep.LXCIP))
	fmt.Fprintf(f, "#define LXC_ID %#x\n", ep.U16ID())
	fmt.Fprintf(f, "#define LXC_ID_NB %#x\n", common.Swab16(ep.U16ID()))
	fmt.Fprintf(f, "#define SECLABEL_NB %#x\n", common.Swab32(ep.SecLabelID))
	fmt.Fprintf(f, "#define SECLABEL %#x\n", ep.SecLabelID)
	fmt.Fprintf(f, "#define POLICY_MAP %s\n", path.Base(policyMapPath))
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

	if err = d.lxcMap.WriteEndpoint(ep); err != nil {
		os.RemoveAll(lxcDir)
		os.RemoveAll(policyMapPath)
		log.Warningf("Unable to update BPF map: %s", err)
		return fmt.Errorf("Unable to update eBPF map: %s", err)
	}

	// Only generate & populate policy map if a seclabel and consumer model is set up
	if ep.Consumable != nil {
		ep.Consumable.AddMap(policyMap)
		if err := d.RegenerateEndpoint(ep); err != nil {
			ep.Consumable.RemoveMap(policyMap)
			os.RemoveAll(policyMapPath)
			os.RemoveAll(lxcDir)
			log.Warningf("Unable to generate policy map for '%s': %s", policyMapPath, err)
			return fmt.Errorf("Unable to generate policy map for '%s': %s", policyMapPath, err)
		}
	}

	args := []string{d.libDir, ep.ID, ep.IfName}
	out, err := exec.Command(filepath.Join(d.libDir, "join_ep.sh"), args...).CombinedOutput()
	if err != nil {
		if ep.Consumable != nil {
			ep.Consumable.RemoveMap(policyMap)
		}
		os.RemoveAll(lxcDir)
		log.Warningf("Command execution failed: %s", err)
		log.Warningf("Command output:\n%s", out)
		return fmt.Errorf("error: \"%s\"\noutput: \"%s\"", err, out)
	}
	log.Infof("Command successful:\n%s", out)
	return nil
}

// EndpointJoin sets up the endpoint working directory.
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

// EndpointLeave cleans the directory used by the endpoint epID and all relevant details
// with the epID.
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

	if ep := d.getEndpoint(epID); ep != nil {
		if ep.Consumable != nil {
			ep.Consumable.RemoveMap(ep.PolicyMap)
		}
	}

	// Clear policy map
	os.RemoveAll(common.PolicyMapPath + epID)

	d.deleteEndpoint(epID)

	log.Infof("Command successful:\n%s", out)

	return nil
}
