package daemon

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"

	"github.com/noironetworks/cilium-net/bpf/geneve"
	"github.com/noironetworks/cilium-net/bpf/policymap"
	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"
)

var r, _ = regexp.Compile("^[0-9]+$")

func isValidID(id string) bool {
	return r.MatchString(id)
}

func writeGeneve(lxcDir string, ep *types.Endpoint) ([]byte, error) {

	// Write container options values for each available option in
	// bpf/lib/geneve.h
	// GENEVE_CLASS_EXPERIMENTAL, GENEVE_TYPE_SECLABEL
	err := geneve.WriteOpts(filepath.Join(lxcDir, "geneve_opts.cfg"), "0xffff", "0x1", "4", fmt.Sprintf("%08x", ep.SecLabelID))
	if err != nil {
		log.Warningf("Could not write geneve options %s", err)
		return nil, err
	}

	_, rawData, err := geneve.ReadOpts(filepath.Join(lxcDir, "geneve_opts.cfg"))
	if err != nil {
		log.Warningf("Could not read geneve options %s", err)
		return nil, err
	}

	return rawData, nil
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
	id := ""
	if endpointID != "" {
		id = common.CiliumPrefix + endpointID
	} else if dockerID != "" {
		id = common.DockerPrefix + dockerID
	} else {
		return nil
	}

	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	if ep, ok := d.endpoints[id]; ok {
		ep.SetSecLabel(labels)
		epCopy := *ep
		return &epCopy
	}

	return nil
}

// EndpointGet returns a copy of the endpoint for the given endpointID, or nil if the
// endpoint was not found.
func (d *Daemon) EndpointGet(endpointID string) (*types.Endpoint, error) {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	if ep, ok := d.endpoints[common.CiliumPrefix+endpointID]; ok {
		epCopy := *ep
		return &epCopy, nil
	}
	return nil, nil
}

// EndpointsGet returns a copy of all the endpoints or nil if there are no endpoints.
func (d *Daemon) EndpointsGet() ([]types.Endpoint, error) {
	eps := []types.Endpoint{}
	d.endpointsMU.Lock()
	for _, v := range d.endpoints {
		epCopy := *v
		eps = append(eps, epCopy)
	}
	d.endpointsMU.Unlock()
	if len(eps) == 0 {
		return nil, nil
	}
	return eps, nil
}

func (d *Daemon) deleteEndpoint(endpointID string) {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	if ep, ok := d.endpoints[common.CiliumPrefix+endpointID]; ok {
		delete(d.endpoints, common.DockerPrefix+ep.DockerID)
		delete(d.endpoints, common.CiliumPrefix+endpointID)
	}
}

func (d *Daemon) createBPFFile(f *os.File, ep *types.Endpoint, geneveOpts []byte) error {
	fw := bufio.NewWriter(f)

	fmt.Fprint(fw, "/*\n")
	if ep.DockerID == "" {
		fmt.Fprintf(fw, " * Docker Network ID: %s\n", ep.DockerNetwork)
	} else {
		fmt.Fprintf(fw, " * Docker Container ID: %s\n", ep.DockerID)
	}
	policyMapPath := common.PolicyMapPath + ep.ID

	fmt.Fprintf(fw, " * MAC: %s\n"+
		" * IPv6 address: %s\n"+
		" * IPv4 address: %s\n"+
		" * SecLabel: %#x\n"+
		" * PolicyMap: %s\n"+
		" * NodeMAC: %s\n"+
		" */\n\n",
		ep.LXCMAC, ep.LXCIP, ep.IPv4Address(d.ipv4Range),
		ep.SecLabelID, path.Base(policyMapPath), ep.NodeMAC)

	secCtxLabels, err := d.GetLabels(int(ep.SecLabelID))
	if err != nil {
		return err
	}

	fw.WriteString("/*\n")
	fw.WriteString(" * Labels:\n")
	for _, v := range secCtxLabels.Labels {
		fmt.Fprintf(fw, " * - %s\n", v)
	}
	fw.WriteString(" */\n\n")

	fw.WriteString(common.FmtDefineAddress("LXC_MAC", ep.LXCMAC))
	fw.WriteString(common.FmtDefineAddress("LXC_IP", ep.LXCIP))
	fmt.Fprintf(fw, "#define LXC_ID %#x\n", ep.U16ID())
	fmt.Fprintf(fw, "#define LXC_ID_NB %#x\n", common.Swab16(ep.U16ID()))
	fmt.Fprintf(fw, "#define SECLABEL_NB %#x\n", common.Swab32(ep.SecLabelID))
	fmt.Fprintf(fw, "#define SECLABEL %#x\n", ep.SecLabelID)
	fmt.Fprintf(fw, "#define POLICY_MAP %s\n", path.Base(policyMapPath))
	fmt.Fprintf(fw, "%s\n", ep.GetFmtOpt("DISABLE_POLICY_ENFORCEMENT"))
	fmt.Fprintf(fw, "%s\n", ep.GetFmtOpt("ENABLE_NAT46"))
	fmt.Fprintf(fw, "%s\n", ep.GetFmtOpt("DROP_NOTIFY"))
	fw.WriteString(common.FmtDefineAddress("NODE_MAC", ep.NodeMAC))

	fw.WriteString("#define LXC_PORT_MAPPINGS ")
	for _, m := range ep.PortMap {
		// Write mappings directly in network byte order so we don't have
		// to convert it in the fast path
		fmt.Fprintf(fw, "{%#x,%#x},", common.Swab16(m.From), common.Swab16(m.To))
	}
	fw.WriteString("\n")

	fw.WriteString(common.FmtDefineArray("GENEVE_OPTS", geneveOpts))

	return fw.Flush()
}

func (d *Daemon) createBPF(rEP types.Endpoint) error {
	if !isValidID(rEP.ID) {
		return fmt.Errorf("invalid ID: %s", rEP.ID)
	}

	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	ep, ok := d.endpoints[common.CiliumPrefix+rEP.ID]
	if !ok {
		log.Warningf("Unable to find endpoint\n")
		return fmt.Errorf("Unable to find endpoint\n")
	}

	lxcDir := filepath.Join(".", ep.ID)

	geneveOpts, err := writeGeneve(lxcDir, ep)
	if err != nil {
		return err
	}

	f, err := os.Create(filepath.Join(lxcDir, "lxc_config.h"))
	if err != nil {
		os.RemoveAll(lxcDir)
		log.Warningf("Failed to create container headerfile: %s", err)
		return fmt.Errorf("Failed to create temporary directory: \"%s\"", err)

	}
	err = d.createBPFFile(f, ep, geneveOpts)
	if err != nil {
		f.Close()
		os.RemoveAll(lxcDir)
		log.Warningf("Failed to create container headerfile: %s", err)
		return fmt.Errorf("Failed to create temporary directory: \"%s\"", err)
	}
	f.Close()

	policyMapPath := common.PolicyMapPath + ep.ID
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
		return fmt.Errorf("error: %q command output: %q", err, out)
	}
	log.Infof("Command successful:\n%s", out)
	return nil
}

// EndpointJoin sets up the endpoint working directory.
func (d *Daemon) EndpointJoin(ep types.Endpoint) error {
	if !isValidID(ep.ID) {
		return fmt.Errorf("invalid ID: %s", ep.ID)
	}
	lxcDir := filepath.Join(".", ep.ID)

	if err := os.MkdirAll(lxcDir, 0777); err != nil {
		log.Warningf("Failed to create container temporary directory: %s", err)
		return fmt.Errorf("failed to create temporary directory: %s", err)
	}

	if ep.Opts == nil {
		ep.Opts = types.EPOpts{}
		ep.Opts[common.DisablePolicyEnforcement] = d.disablePolicy
		ep.Opts[common.EnableNAT46] = false
		ep.Opts[common.EnableDropNotify] = true
	} else {
		if _, exists := ep.Opts[common.DisablePolicyEnforcement]; !exists {
			ep.Opts[common.DisablePolicyEnforcement] = d.disablePolicy
		}
		if _, exists := ep.Opts[common.EnableNAT46]; !exists {
			ep.Opts[common.EnableNAT46] = false
		}
		if _, exists := ep.Opts[common.EnableDropNotify]; !exists {
			ep.Opts[common.EnableDropNotify] = true
		}
	}

	d.insertEndpoint(&ep)

	return nil
}

// EndpointLeave cleans the directory used by the endpoint epID and all relevant details
// with the epID.
func (d *Daemon) EndpointLeave(epID string) error {
	// Preventing someone from deleting important directories
	if !isValidID(epID) {
		return fmt.Errorf("invalid ID: %s", epID)
	}
	if _, ok := d.endpoints[common.CiliumPrefix+epID]; !ok {
		return fmt.Errorf("endpoint %s not found", epID)
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

	if ep, err := d.EndpointGet(epID); err != nil {
		log.Warningf("Unable to get endpoint %s from daemon.", epID)
	} else if ep.Consumable != nil {
		ep.Consumable.RemoveMap(ep.PolicyMap)
	}

	// Clear policy map
	os.RemoveAll(common.PolicyMapPath + epID)

	d.deleteEndpoint(epID)

	log.Infof("Command successful:\n%s", out)

	return nil
}

// EndpointUpdate updates the given endpoint and recompiles the bpf map.
func (d *Daemon) EndpointUpdate(epID string, opts types.EPOpts) error {
	// Preventing someone from deleting important directories
	if !isValidID(epID) {
		return fmt.Errorf("invalid ID: %s", epID)
	}
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	ep, ok := d.endpoints[common.CiliumPrefix+epID]
	if !ok {
		return fmt.Errorf("endpoint %s not found", epID)
	}
	for k, v := range opts {
		ep.Opts[k] = v
	}

	lxcDir := filepath.Join(".", ep.ID+"_update")
	if err := os.MkdirAll(lxcDir, 0777); err != nil {
		log.Warningf("Update failed: failed to create container temporary directory: %s", err)
		return fmt.Errorf("update failed: failed to create temporary directory: %s", err)
	}

	geneveOpts, err := writeGeneve(lxcDir, ep)
	if err != nil {
		return err
	}

	f, err := os.Create(filepath.Join(lxcDir, "lxc_config.h"))
	if err != nil {
		os.RemoveAll(lxcDir)
		log.Warningf("Update failed: failed to create lxc_config.h: %s", err)
		return fmt.Errorf("update failed: failed to create lxc_config.h: %s", err)

	}
	err = d.createBPFFile(f, ep, geneveOpts)
	if err != nil {
		f.Close()
		os.RemoveAll(lxcDir)
		log.Warningf("update failed: failed to create container headerfile: %s", err)
		return fmt.Errorf("update failed: failed to create temporary directory: %s", err)
	}
	f.Close()

	args := []string{d.libDir, (ep.ID + "_update"), ep.IfName}
	out, err := exec.Command(filepath.Join(d.libDir, "join_ep.sh"), args...).CombinedOutput()
	if err != nil {
		os.RemoveAll(lxcDir)
		log.Warningf("Update execution failed: %s", err)
		log.Warningf("Command output:\n%s", out)
		return fmt.Errorf("error: %q command output: %q", err, out)
	}
	lxcDirOrg := filepath.Join(".", ep.ID)
	os.RemoveAll(lxcDirOrg)
	err = os.Rename(lxcDir, lxcDirOrg)
	if err != nil {
		os.RemoveAll(lxcDir)
		log.Warningf("Update execution failed: %s", err)
		return fmt.Errorf("update execution failed: %s", err)
	}

	log.Infof("Update successful performed:\n%s", out)

	return nil
}
