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
	err := geneve.WriteOpts(filepath.Join(lxcDir, "geneve_opts.cfg"), "0xffff", "0x1", "4", fmt.Sprintf("%08x", ep.SecLabel.ID))
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

// InsertEndpoint inserts the ep in the endpoints map.
func (d *Daemon) InsertEndpoint(ep *types.Endpoint) {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	d.insertEndpoint(ep)
}

// insertEndpoint inserts the ep in the endpoints map. To be used with endpointsMU locked.
func (d *Daemon) insertEndpoint(ep *types.Endpoint) {
	d.endpoints[common.CiliumPrefix+ep.ID] = ep
	if ep.DockerID != "" {
		d.endpoints[common.DockerPrefix+ep.DockerID] = ep
	}
	if ep.DockerEndpointID != "" {
		d.endpoints[common.DockerEPPrefix+ep.DockerEndpointID] = ep
	}
}

// Sets the given secLabel on the endpoint with the given endpointID. Returns a pointer of
// a copy endpoint if the endpoint was found, nil otherwise.
func (d *Daemon) setEndpointSecLabel(endpointID, dockerID, dockerEPID string, labels *types.SecCtxLabel) *types.Endpoint {
	id := ""
	if endpointID != "" {
		id = common.CiliumPrefix + endpointID
	} else if dockerID != "" {
		id = common.DockerPrefix + dockerID
	} else if dockerEPID != "" {
		id = common.DockerEPPrefix + dockerEPID
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

// EndpointGetByDockerEPID returns a copy of the endpoint for the given dockerEPID, or nil
// if the endpoint was not found.
func (d *Daemon) EndpointGetByDockerEPID(dockerEPID string) (*types.Endpoint, error) {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	if ep, ok := d.endpoints[common.DockerEPPrefix+dockerEPID]; ok {
		epCopy := *ep
		return &epCopy, nil
	}
	return nil, nil
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
	epsSet := map[*types.Endpoint]bool{}
	for _, v := range d.endpoints {
		epsSet[v] = true
	}
	if len(epsSet) == 0 {
		return nil, nil
	}
	for k := range epsSet {
		epCopy := *k
		eps = append(eps, epCopy)
	}
	return eps, nil
}

func (d *Daemon) deleteEndpoint(endpointID string) {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	if ep, ok := d.endpoints[common.CiliumPrefix+endpointID]; ok {
		delete(d.endpoints, common.DockerPrefix+ep.DockerID)
		delete(d.endpoints, common.DockerEPPrefix+ep.DockerEndpointID)
		delete(d.endpoints, common.CiliumPrefix+endpointID)
	}
}

func (d *Daemon) createBPFFile(f *os.File, ep *types.Endpoint, geneveOpts []byte) error {
	fw := bufio.NewWriter(f)

	fmt.Fprint(fw, "/*\n")
	if epStr64, err := ep.Base64(); err == nil {
		fmt.Fprintf(fw, " * %s%s:%s\n * \n", common.CiliumCHeaderPrefix, common.Version, epStr64)
	} else {
		log.Warningf("Unable to create a base64 for endpoint %+v: %s\n", ep, err)
	}
	if ep.DockerID == "" {
		fmt.Fprintf(fw, " * Docker Network ID: %s\n", ep.DockerNetworkID)
		fmt.Fprintf(fw, " * Docker Endpoint ID: %s\n", ep.DockerEndpointID)
	} else {
		fmt.Fprintf(fw, " * Docker Container ID: %s\n", ep.DockerID)
	}
	policyMapPath := common.PolicyMapPath + ep.ID

	fmt.Fprintf(fw, " * MAC: %s\n"+
		" * IPv6 address: %s\n"+
		" * IPv4 address: %s\n"+
		" * SecLabelID: %#x\n"+
		" * PolicyMap: %s\n"+
		" * NodeMAC: %s\n"+
		" */\n\n",
		ep.LXCMAC, ep.LXCIP, ep.IPv4Address(d.conf.IPv4Range),
		ep.SecLabel.ID, path.Base(policyMapPath), ep.NodeMAC)

	fw.WriteString("/*\n")
	fw.WriteString(" * Labels:\n")
	if len(ep.SecLabel.Labels) == 0 {
		fmt.Fprintf(fw, " * - %s\n", "(no labels)")
	} else {
		for _, v := range ep.SecLabel.Labels {
			fmt.Fprintf(fw, " * - %s\n", v)
		}
	}
	fw.WriteString(" */\n\n")

	fw.WriteString(common.FmtDefineAddress("LXC_MAC", ep.LXCMAC))
	fw.WriteString(common.FmtDefineAddress("LXC_IP", ep.LXCIP))
	fmt.Fprintf(fw, "#define LXC_ID %#x\n", ep.U16ID())
	fmt.Fprintf(fw, "#define LXC_ID_NB %#x\n", common.Swab16(ep.U16ID()))
	fmt.Fprintf(fw, "#define SECLABEL_NB %#x\n", common.Swab32(ep.SecLabel.ID))
	fmt.Fprintf(fw, "#define SECLABEL %#x\n", ep.SecLabel.ID)
	fmt.Fprintf(fw, "#define POLICY_MAP %s\n", path.Base(policyMapPath))
	fmt.Fprintf(fw, "#define CT_MAP_SIZE 4096\n")
	fmt.Fprintf(fw, "#define CT_MAP %s\n", path.Base(common.BPFMapCT+ep.ID))

	for k, _ := range ep.Opts {
		fmt.Fprintf(fw, "%s\n", ep.GetFmtOpt(k))
	}

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

func (d *Daemon) createPolicyMap(ep *types.Endpoint, policyMapPath string) error {
	policyMap, err := policymap.OpenMap(policyMapPath)
	if err != nil {
		log.Warningf("Could not create policy BPF map '%s': %s", policyMapPath, err)
		return fmt.Errorf("could not create policy BPF map '%s': %s", policyMapPath, err)
	}

	ep.PolicyMap = policyMap

	if err = d.conf.LXCMap.WriteEndpoint(ep); err != nil {
		os.RemoveAll(policyMapPath)
		log.Warningf("Unable to update BPF map: %s", err)
		return fmt.Errorf("Unable to update eBPF map: %s", err)
	}

	// Only generate & populate policy map if a seclabel and consumer model is set up
	if ep.Consumable != nil {
		ep.Consumable.AddMap(policyMap)
		if err := d.regenerateEndpoint(ep); err != nil {
			ep.Consumable.RemoveMap(policyMap)
			os.RemoveAll(policyMapPath)
			log.Warningf("Unable to generate policy map for '%s': %s", policyMapPath, err)
			return fmt.Errorf("Unable to generate policy map for '%s': %s", policyMapPath, err)
		}
	}
	return nil
}

func (d *Daemon) createBPFMAPs(epID string) error {
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

	return d.updateBPFMaps(ep, nil, "", false)
}

// updateBPFMaps refreshes the BPF maps for the endpoint epID. The opts values are
// replaced for the given epID. if endpointSuffix is set it can used as a suffix for the
// endpoint directory and policy map names.
func (d *Daemon) updateBPFMaps(ep *types.Endpoint, opts types.EPOpts, endpointSuffix string, update bool) error {
	if !ep.ApplyOpts(opts) && update {
		// No changes have been applied, skip update
		return nil
	}

	lxcDir := filepath.Join(".", ep.ID+endpointSuffix)
	if err := os.MkdirAll(lxcDir, 0777); err != nil {
		return fmt.Errorf("failed to create temporary directory: %s", err)
	}

	geneveOpts, err := writeGeneve(lxcDir, ep)
	if err != nil {
		return err
	}

	f, err := os.Create(filepath.Join(lxcDir, common.CHeaderFileName))
	if err != nil {
		os.RemoveAll(lxcDir)
		return fmt.Errorf("failed to create lxc_config.h: %s", err)

	}
	err = d.createBPFFile(f, ep, geneveOpts)
	if err != nil {
		f.Close()
		os.RemoveAll(lxcDir)
		return fmt.Errorf("failed to create temporary directory: %s", err)
	}
	f.Close()

	policyMapPath := common.PolicyMapPath + ep.ID + endpointSuffix
	if err := d.createPolicyMap(ep, policyMapPath); err != nil {
		os.RemoveAll(lxcDir)
		return fmt.Errorf("failed to create container policymap file: %s", err)
	}

	args := []string{d.conf.LibDir, (ep.ID + endpointSuffix), ep.IfName}
	out, err := exec.Command(filepath.Join(d.conf.LibDir, "join_ep.sh"), args...).CombinedOutput()
	if err != nil {
		if ep.Consumable != nil {
			if policyMap, err := policymap.OpenMap(policyMapPath); err == nil {
				ep.Consumable.RemoveMap(policyMap)
			}
		}
		os.RemoveAll(policyMapPath)
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
		ep.Opts[common.DisablePolicyEnforcement] = d.conf.DisablePolicy
		ep.Opts[common.EnableNAT46] = false
		ep.Opts[common.EnableDropNotify] = true
	} else {
		if _, exists := ep.Opts[common.DisablePolicyEnforcement]; !exists {
			ep.Opts[common.DisablePolicyEnforcement] = d.conf.DisablePolicy
		}
		if _, exists := ep.Opts[common.EnableNAT46]; !exists {
			ep.Opts[common.EnableNAT46] = false
		}
		if _, exists := ep.Opts[common.EnableDropNotify]; !exists {
			ep.Opts[common.EnableDropNotify] = true
		}
	}

	d.InsertEndpoint(&ep)

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

	if err := d.conf.LXCMap.DeleteElement(epID); err != nil {
		log.Warningf("Unable to remove endpoint from map: %s", err)
	}

	args := []string{d.conf.LibDir, epID}
	out, err := exec.Command(filepath.Join(d.conf.LibDir, "leave_ep.sh"), args...).CombinedOutput()
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

// EndpointLeaveByDockerEPID cleans the directory used by the endpoint dockerEPID and all
// relevant details with the epID.
func (d *Daemon) EndpointLeaveByDockerEPID(dockerEPID string) error {
	if ep, ok := d.endpoints[common.DockerEPPrefix+dockerEPID]; !ok {
		return fmt.Errorf("endpoint %s not found", dockerEPID)
	} else {
		return d.EndpointLeave(ep.ID)
	}
}

func (d *Daemon) ApplyEndpointChanges(ep *types.Endpoint, opts types.EPOpts) error {
	endpointSuffix := "_update"
	if err := d.updateBPFMaps(ep, opts, endpointSuffix, true); err != nil {
		return err
	}

	policyMapPath := common.PolicyMapPath + ep.ID + endpointSuffix
	lxcDir := filepath.Join(".", (ep.ID + endpointSuffix))

	moveDir := func(oldDir, newDir string) error {
		os.RemoveAll(newDir)
		if err := os.Rename(oldDir, newDir); err != nil {
			os.RemoveAll(policyMapPath)
			os.RemoveAll(lxcDir)
			return err
		}
		return nil
	}

	lxcDirOrg := filepath.Join(".", ep.ID)
	if err := moveDir(lxcDir, lxcDirOrg); err != nil {
		return err
	}

	policyMapPathOrig := common.PolicyMapPath + ep.ID
	if err := moveDir(policyMapPath, policyMapPathOrig); err != nil {
		return err
	}

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

	return d.ApplyEndpointChanges(ep, opts)
}

// EndpointSave saves the endpoint in the daemon internal endpoint map.
func (d *Daemon) EndpointSave(ep types.Endpoint) error {
	if !isValidID(ep.ID) {
		return fmt.Errorf("invalid ID: %s", ep.ID)
	}
	d.InsertEndpoint(&ep)
	return nil
}
