package daemon

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"

	"github.com/op/go-logging"

	"github.com/noironetworks/cilium-net/bpf/geneve"
	"github.com/noironetworks/cilium-net/bpf/policymap"
	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"
)

var r, _ = regexp.Compile("^[0-9]+$")

func isValidID(id string) bool {
	return r.MatchString(id)
}

func (d *Daemon) lookupCiliumEndpoint(id string) *types.Endpoint {
	if ep, ok := d.endpoints[id]; ok {
		return ep
	} else {
		return nil
	}
}

func (d *Daemon) lookupDockerEndpoint(id string) *types.Endpoint {
	if ep, ok := d.endpointsDockerEP[id]; ok {
		return ep
	} else {
		return nil
	}
}

func (d *Daemon) lookupDockerID(id string) *types.Endpoint {
	if ep, ok := d.endpointsDocker[id]; ok {
		return ep
	} else {
		return nil
	}
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

// Public API to insert an endpoint without connecting it to a container
func (d *Daemon) InsertEndpoint(ep *types.Endpoint) {
	if !isValidID(ep.ID) {
		return
	}

	d.endpointsMU.Lock()
	d.insertEndpoint(ep)
	d.endpointsMU.Unlock()
}

// insertEndpoint inserts the ep in the endpoints map. To be used with endpointsMU locked.
func (d *Daemon) insertEndpoint(ep *types.Endpoint) {
	d.endpoints[ep.ID] = ep

	if ep.DockerID != "" {
		d.endpointsDocker[ep.DockerID] = ep
	}

	if ep.DockerEndpointID != "" {
		d.endpointsDockerEP[ep.DockerEndpointID] = ep
	}
}

// Sets the given secLabel on the endpoint with the given endpointID. Returns a pointer of
// a copy endpoint if the endpoint was found, nil otherwise.
func (d *Daemon) setEndpointSecLabel(endpointID, dockerID, dockerEPID string, labels *types.SecCtxLabel) *types.Endpoint {
	var (
		ep *types.Endpoint
		ok bool
	)

	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	if endpointID != "" {
		ep, ok = d.endpoints[endpointID]
	} else if dockerID != "" {
		ep, ok = d.endpointsDocker[dockerID]
	} else if dockerEPID != "" {
		ep, ok = d.endpointsDockerEP[dockerEPID]
	} else {
		return nil
	}

	if ok {
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

	if ep := d.lookupDockerEndpoint(dockerEPID); ep != nil {
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

	if ep := d.lookupCiliumEndpoint(endpointID); ep != nil {
		epCopy := *ep
		return &epCopy, nil
	}

	return nil, nil
}

// EndpointsGet returns a copy of all the endpoints or nil if there are no endpoints.
func (d *Daemon) EndpointsGet() ([]types.Endpoint, error) {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

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

	if ep := d.lookupCiliumEndpoint(endpointID); ep != nil {
		delete(d.endpointsDocker, ep.DockerID)
		delete(d.endpointsDockerEP, ep.DockerEndpointID)
		delete(d.endpoints, endpointID)
	}
}

func (d *Daemon) writeBPFHeader(lxcDir string, ep *types.Endpoint, geneveOpts []byte) error {
	headerPath := filepath.Join(lxcDir, common.CHeaderFileName)
	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %s", headerPath, err)

	}
	defer f.Close()

	fw := bufio.NewWriter(f)

	fmt.Fprint(fw, "/*\n")

	if epStr64, err := ep.Base64(); err == nil {
		fmt.Fprintf(fw, " * %s%s:%s\n * \n", common.CiliumCHeaderPrefix,
			common.Version, epStr64)
	} else {
		log.Warningf("Unable to create a base64 for endpoint %+v: %s\n", ep, err)
	}

	if ep.DockerID == "" {
		fmt.Fprintf(fw, " * Docker Network ID: %s\n", ep.DockerNetworkID)
		fmt.Fprintf(fw, " * Docker Endpoint ID: %s\n", ep.DockerEndpointID)
	} else {
		fmt.Fprintf(fw, " * Docker Container ID: %s\n", ep.DockerID)
	}

	fmt.Fprintf(fw, ""+
		" * MAC: %s\n"+
		" * IPv6 address: %s\n"+
		" * IPv4 address: %s\n"+
		" * SecLabelID: %#x\n"+
		" * PolicyMap: %s\n"+
		" * NodeMAC: %s\n"+
		" */\n\n",
		ep.LXCMAC, ep.LXCIP, ep.IPv4Address(d.conf.IPv4Range),
		ep.SecLabel.ID, path.Base(ep.PolicyMapPath()), ep.NodeMAC)

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
	fw.WriteString(common.FmtDefineAddress("NODE_MAC", ep.NodeMAC))
	fw.WriteString(common.FmtDefineArray("GENEVE_OPTS", geneveOpts))
	fmt.Fprintf(fw, "#define LXC_ID %#x\n", ep.U16ID())
	fmt.Fprintf(fw, "#define LXC_ID_NB %#x\n", common.Swab16(ep.U16ID()))
	fmt.Fprintf(fw, "#define SECLABEL_NB %#x\n", common.Swab32(ep.SecLabel.ID))
	fmt.Fprintf(fw, "#define SECLABEL %#x\n", ep.SecLabel.ID)
	fmt.Fprintf(fw, "#define POLICY_MAP %s\n", path.Base(ep.PolicyMapPath()))
	fmt.Fprintf(fw, "#define CT_MAP_SIZE 4096\n")
	fmt.Fprintf(fw, "#define CT_MAP %s\n", path.Base(common.BPFMapCT+ep.ID))

	for k, _ := range ep.Opts {
		fmt.Fprintf(fw, "%s\n", ep.GetFmtOpt(k))
	}

	fw.WriteString("#define LXC_PORT_MAPPINGS ")
	for _, m := range ep.PortMap {
		// Write mappings directly in network byte order so we don't have
		// to convert it in the fast path
		fmt.Fprintf(fw, "{%#x,%#x},", common.Swab16(m.From), common.Swab16(m.To))
	}
	fw.WriteString("\n")

	return fw.Flush()
}

func (d *Daemon) createBPFMAPs(epID string) error {
	// Preventing someone from deleting important directories
	if !isValidID(epID) {
		return fmt.Errorf("invalid ID: %s", epID)
	}
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	ep, ok := d.endpoints[epID]
	if !ok {
		return fmt.Errorf("endpoint %s not found", epID)
	}

	return d.regenerateBPF(ep, filepath.Join(".", ep.ID))
}

// regenerateBPF rewrites all headers and updates all BPF maps to reflect the
// specified endpoint.
//
// If endpointSuffix is set, it will be appended to the container directory to
// allow writing to a temporary directory and then atomically rename it.
func (d *Daemon) regenerateBPF(ep *types.Endpoint, lxcDir string) error {
	var err error
	createdPolicyMap := false

	policyMapPath := ep.PolicyMapPath()

	// Cleanup on failure
	defer func() {
		if err != nil {
			if createdPolicyMap {
				// Remove policy map file only if it was created
				// in this update cycle
				if ep.Consumable != nil {
					ep.Consumable.RemoveMap(ep.PolicyMap)
				}

				os.RemoveAll(policyMapPath)
				ep.PolicyMap = nil
			}

			// Always remove endpoint directory, if this was a subsequent
			// update call, it was the responsibility of the updater to
			// to provide an endpoint suffix to not bluntly overwrite the
			// existing directory.
			os.RemoveAll(lxcDir)
		}
	}()

	if ep.PolicyMap == nil {
		ep.PolicyMap, createdPolicyMap, err = policymap.OpenMap(policyMapPath)
		if err != nil {
			return err
		}
	}

	// Only generate & populate policy map if a seclabel and consumer model is set up
	if ep.Consumable != nil {
		ep.Consumable.AddMap(ep.PolicyMap)

		// The policy is only regenerated but the endpoint is not
		// regenerated as we regenerate below anyway.
		if err := d.regenerateEndpointPolicy(ep, false); err != nil {
			return fmt.Errorf("Unable to regenerate policy for '%s': %s",
				ep.PolicyMap.String(), err)
		}
	}

	if err := os.MkdirAll(lxcDir, 0777); err != nil {
		return fmt.Errorf("Failed to create endpoint directory: %s", err)
	}

	geneveOpts, err := writeGeneve(lxcDir, ep)
	if err != nil {
		return err
	}

	err = d.writeBPFHeader(lxcDir, ep, geneveOpts)
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %s", err)
	}

	if err := d.conf.LXCMap.WriteEndpoint(ep); err != nil {
		return fmt.Errorf("Unable to update eBPF map: %s", err)
	}

	args := []string{d.conf.LibDir, lxcDir, ep.IfName}
	out, err := exec.Command(filepath.Join(d.conf.LibDir, "join_ep.sh"), args...).CombinedOutput()
	if err != nil {
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
	}

	if _, exists := ep.Opts[types.OptionDisableConntrack]; !exists {
		ep.Opts[types.OptionDisableConntrack] = d.conf.DisableConntrack
	}
	if _, exists := ep.Opts[types.OptionDisablePolicy]; !exists {
		ep.Opts[types.OptionDisablePolicy] = d.conf.DisablePolicy
	}
	if _, exists := ep.Opts[types.OptionDebug]; !exists {
		ep.Opts[types.OptionDebug] = log.IsEnabledFor(logging.DEBUG)
	}
	if _, exists := ep.Opts[types.OptionNAT46]; !exists {
		ep.Opts[types.OptionNAT46] = false
	}
	if _, exists := ep.Opts[types.OptionDropNotify]; !exists {
		ep.Opts[types.OptionDropNotify] = true
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

	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	ep := d.lookupCiliumEndpoint(epID)
	if ep == nil {
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

	if ep.Consumable != nil {
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
	// FIXME: Validate dockerEPID?

	d.endpointsMU.Lock()
	if ep := d.lookupDockerEndpoint(dockerEPID); ep != nil {
		d.endpointsMU.Unlock()
		return d.EndpointLeave(ep.ID)
	} else {
		d.endpointsMU.Unlock()
		return fmt.Errorf("endpoint %s not found", dockerEPID)
	}
}

func (d *Daemon) regenerateEndpoint(ep *types.Endpoint) error {
	// This is the temporary directory to store the generated headers,
	// the original existing directory is not overwritten until all
	// generation has succeeded.
	origDir := filepath.Join(".", ep.ID)
	tmpDir := origDir + "_update"
	backupDir := origDir + "_backup"

	if err := d.regenerateBPF(ep, tmpDir); err != nil {
		return err
	}

	// Attempt to move the original endpoint directory to a backup location
	if err := os.Rename(origDir, backupDir); err != nil {
		os.RemoveAll(tmpDir)
		return fmt.Errorf("Unable to create backup of endpoint directory: %s", err)
	}

	// Move new endpoint directory in place, upon failure, restore backup
	if err := os.Rename(tmpDir, origDir); err != nil {
		os.RemoveAll(tmpDir)

		if err2 := os.Rename(backupDir, origDir); err2 != nil {
			log.Warningf("Restoring the backup directory for %s for endpoint "+
				"%s did not succeed, the endpoint is now in an inconsistent state",
				backupDir, ep.String())
			return err2
		}

		log.Warningf("Restored original endpoint directory, atomic replace failed: %s", err)
		return err
	}

	os.RemoveAll(backupDir)
	log.Infof("Successfully regenerated program for endpoint %s", ep.String())

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

	if ep := d.lookupCiliumEndpoint(epID); ep != nil {
		if !ep.ApplyOpts(opts) {
			// No changes have been applied, skip update
			return nil
		}

		return d.regenerateEndpoint(ep)
	} else {
		return fmt.Errorf("endpoint %s not found", epID)
	}
}

// EndpointSave saves the endpoint in the daemon internal endpoint map.
func (d *Daemon) EndpointSave(ep types.Endpoint) error {
	if !isValidID(ep.ID) {
		return fmt.Errorf("invalid ID: %s", ep.ID)
	}
	d.InsertEndpoint(&ep)
	return nil
}

func (d *Daemon) EndpointLabelsGet(epID string) (*types.OpLabels, error) {
	d.containersMU.Lock()
	defer d.containersMU.Unlock()
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	ep := d.lookupCiliumEndpoint(epID)
	if ep == nil {
		return nil, fmt.Errorf("endpoint %s not found", epID)
	}

	cont := d.containers[ep.DockerID]
	if cont == nil {
		return nil, fmt.Errorf("container %s not found in cache", ep.DockerID)
	}

	cpy := types.OpLabels(cont.OpLabels)
	return &cpy, nil
}

func (d *Daemon) EndpointLabelsUpdate(epID string, op types.LabelOP, labels types.Labels) error {
	if !isValidID(epID) {
		return fmt.Errorf("invalid ID: %s", epID)
	}

	ep, err := d.EndpointGet(epID)
	if err != nil {
		return err
	}

	labels = d.conf.ValidLabelPrefixes.FilterLabels(labels)

	d.containersMU.Lock()
	cont := d.containers[ep.DockerID]
	if cont == nil {
		d.containersMU.Unlock()
		return fmt.Errorf("container not found on cache")
	}

	switch op {
	case types.AddLabelsOp:
		cont.OpLabels.AllLabels.MergeLabels(labels)
		cont.OpLabels.CiliumLabels.MergeLabels(labels)

	case types.DelLabelsOp:
		update := false
		for k, _ := range labels {
			delete(cont.OpLabels.CiliumLabels, k)
			if ep.SecLabel != nil && ep.SecLabel.Labels[k] != nil {
				delete(ep.SecLabel.Labels, k)
				update = true
			}
		}
		if update {
			d.containersMU.Unlock()
			return d.refreshContainerLabels(ep.DockerID, ep.SecLabel.Labels, false)
		}

	case types.EnableLabelsOp:
		for k, v := range labels {
			if cont.OpLabels.CiliumLabels[k] == nil {
				d.containersMU.Unlock()
				return fmt.Errorf("label %s not found, please add it first in order to enable it", v)
			}
		}
		d.containersMU.Unlock()

		if ep.SecLabel != nil {
			ep.SecLabel.Labels.MergeLabels(labels)
			return d.refreshContainerLabels(ep.DockerID, ep.SecLabel.Labels, false)
		} else {
			return d.refreshContainerLabels(ep.DockerID, labels, false)
		}

	case types.DisableLabelsOp:
		update := false
		for k, _ := range labels {
			if ep.SecLabel != nil && ep.SecLabel.Labels[k] != nil {
				delete(ep.SecLabel.Labels, k)
				update = true
			}
		}
		if update {
			d.containersMU.Unlock()
			return d.refreshContainerLabels(ep.DockerID, ep.SecLabel.Labels, false)
		}

	default:
		d.containersMU.Unlock()
		return fmt.Errorf("unknown option %s", op)
	}

	d.containersMU.Unlock()
	return nil
}
