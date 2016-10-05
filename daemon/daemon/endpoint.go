//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package daemon

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"

	"github.com/cilium/cilium/bpf/geneve"
	"github.com/cilium/cilium/bpf/policymap"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
)

func (d *Daemon) lookupCiliumEndpoint(id uint16) *types.Endpoint {
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
		return nil, fmt.Errorf("Could not write geneve options %s", err)
	}

	_, rawData, err := geneve.ReadOpts(filepath.Join(lxcDir, "geneve_opts.cfg"))
	if err != nil {
		log.Warningf("Could not read geneve options %s", err)
		return nil, fmt.Errorf("Could not read geneve options %s", err)
	}

	return rawData, nil
}

// Public API to insert an endpoint without connecting it to a container
func (d *Daemon) InsertEndpoint(ep *types.Endpoint) {
	d.endpointsMU.Lock()
	d.insertEndpoint(ep)
	d.endpointsMU.Unlock()
}

// insertEndpoint inserts the ep in the endpoints map. To be used with endpointsMU locked.
func (d *Daemon) insertEndpoint(ep *types.Endpoint) {
	if ep.Status == nil {
		ep.Status = &types.EndpointStatus{}
	}

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
func (d *Daemon) setEndpointSecLabel(endpointID *uint16, dockerID, dockerEPID string, labels *types.SecCtxLabel) *types.Endpoint {
	var (
		ep *types.Endpoint
		ok bool
	)

	setIfNotEmpty := func(receiver *string, provider string) {
		if receiver != nil && *receiver == "" && provider != "" {
			*receiver = provider
		}
	}

	setIfNotEmptyUint16 := func(receiver *uint16, provider *uint16) {
		if receiver != nil && *receiver == 0 && provider != nil && *provider != 0 {
			*receiver = *provider
		}
	}

	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	if endpointID != nil {
		ep, ok = d.endpoints[*endpointID]
	} else if dockerID != "" {
		ep, ok = d.endpointsDocker[dockerID]
	} else if dockerEPID != "" {
		ep, ok = d.endpointsDockerEP[dockerEPID]
	} else {
		return nil
	}

	if ok {
		setIfNotEmpty(&ep.DockerID, dockerID)
		setIfNotEmpty(&ep.DockerEndpointID, dockerEPID)
		setIfNotEmptyUint16(&ep.ID, endpointID)

		ep.SetSecLabel(labels)
		// Update all IDs in respective MAPs
		d.insertEndpoint(ep)
		return ep.DeepCopy()
	}

	return nil
}

// EndpointGetByDockerID returns a copy of the endpoint for the given dockerEPID, or nil
// if the endpoint was not found.
func (d *Daemon) EndpointGetByDockerID(dockerID string) (*types.Endpoint, error) {
	d.endpointsMU.RLock()
	defer d.endpointsMU.RUnlock()

	if ep := d.lookupDockerID(dockerID); ep != nil {
		return ep.DeepCopy(), nil
	}
	return nil, nil
}

// EndpointGetByDockerEPID returns a copy of the endpoint for the given dockerEPID, or nil
// if the endpoint was not found.
func (d *Daemon) EndpointGetByDockerEPID(dockerEPID string) (*types.Endpoint, error) {
	d.endpointsMU.RLock()
	defer d.endpointsMU.RUnlock()

	if ep := d.lookupDockerEndpoint(dockerEPID); ep != nil {
		return ep.DeepCopy(), nil
	}
	return nil, nil
}

// EndpointGet returns a copy of the endpoint for the given endpointID, or nil if the
// endpoint was not found.
func (d *Daemon) EndpointGet(endpointID uint16) (*types.Endpoint, error) {
	d.endpointsMU.RLock()
	defer d.endpointsMU.RUnlock()

	if ep := d.lookupCiliumEndpoint(endpointID); ep != nil {
		return ep.DeepCopy(), nil
	}

	return nil, nil
}

// EndpointsGet returns a copy of all the endpoints or nil if there are no endpoints.
func (d *Daemon) EndpointsGet() ([]types.Endpoint, error) {
	d.endpointsMU.RLock()
	defer d.endpointsMU.RUnlock()

	eps := []types.Endpoint{}
	epsSet := map[*types.Endpoint]bool{}
	for _, v := range d.endpoints {
		epsSet[v] = true
	}
	if len(epsSet) == 0 {
		return nil, nil
	}
	for k := range epsSet {
		epCopy := k.DeepCopy()
		eps = append(eps, *epCopy)
	}
	return eps, nil
}

func (d *Daemon) deleteEndpoint(endpointID uint16) {

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
		ep.LogStatus(types.Warning, fmt.Sprintf("Unable to create a base64: %s", err))
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
		ep.LXCMAC, ep.IPv6.String(), ep.IPv4.String(),
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
	fw.WriteString(common.FmtDefineAddress("LXC_IP", ep.IPv6))
	if ep.IPv4 != nil {
		fmt.Fprintf(fw, "#define LXC_IPV4 %#x\n", binary.BigEndian.Uint32(ep.IPv4))
	}
	fw.WriteString(common.FmtDefineAddress("NODE_MAC", ep.NodeMAC))
	fw.WriteString(common.FmtDefineArray("GENEVE_OPTS", geneveOpts))
	fmt.Fprintf(fw, "#define LXC_ID %#x\n", ep.ID)
	fmt.Fprintf(fw, "#define LXC_ID_NB %#x\n", common.Swab16(ep.ID))
	fmt.Fprintf(fw, "#define SECLABEL_NB %#x\n", common.Swab32(ep.SecLabel.ID))
	fmt.Fprintf(fw, "#define SECLABEL %#x\n", ep.SecLabel.ID)
	fmt.Fprintf(fw, "#define POLICY_MAP %s\n", path.Base(ep.PolicyMapPath()))
	fmt.Fprintf(fw, "#define CT_MAP_SIZE 4096\n")
	fmt.Fprintf(fw, "#define CT_MAP6 %s\n", path.Base(common.BPFMapCT6+strconv.Itoa(int(ep.ID))))
	fmt.Fprintf(fw, "#define CT_MAP4 %s\n", path.Base(common.BPFMapCT4+strconv.Itoa(int(ep.ID))))

	// Always enable L4 and L3 load balancer for now
	fw.WriteString("#define LB_L3\n")
	fw.WriteString("#define LB_L4\n")

	// Endpoint options
	fw.WriteString(ep.Opts.GetFmtList())

	fw.WriteString("#define LXC_PORT_MAPPINGS ")
	for _, m := range ep.PortMap {
		// Write mappings directly in network byte order so we don't have
		// to convert it in the fast path
		fmt.Fprintf(fw, "{%#x,%#x},", common.Swab16(m.From), common.Swab16(m.To))
	}
	fw.WriteString("\n")

	return fw.Flush()
}

func (d *Daemon) createBPFMAPs(epID uint16) error {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	ep, ok := d.endpoints[epID]
	if !ok {
		return fmt.Errorf("endpoint %d not found", epID)
	}

	err := d.regenerateBPF(ep, filepath.Join(".", strconv.Itoa(int(ep.ID))))
	if err != nil {
		ep.LogStatus(types.Failure, err.Error())
	} else {
		ep.LogStatusOK("Regenerated BPF code")
	}
	return err
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

	if !d.conf.DryMode {
		if ep.PolicyMap == nil {
			ep.PolicyMap, createdPolicyMap, err = policymap.OpenMap(policyMapPath)
			if err != nil {
				return err
			}
		}
	}

	// Only generate & populate policy map if a seclabel and consumer model is set up
	if ep.Consumable != nil {
		if !d.conf.DryMode {
			ep.Consumable.AddMap(ep.PolicyMap)
		}

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

	if !d.conf.DryMode {
		if err := d.conf.LXCMap.WriteEndpoint(ep); err != nil {
			return fmt.Errorf("Unable to update eBPF map: %s", err)
		}

		args := []string{d.conf.LibDir, d.conf.RunDir, lxcDir, ep.IfName}
		out, err := exec.Command(filepath.Join(d.conf.LibDir, "join_ep.sh"), args...).CombinedOutput()
		if err != nil {
			log.Warningf("Command execution failed: %s", err)
			log.Warningf("Command output:\n%s", out)
			return fmt.Errorf("error: %q command output: %q", err, out)
		}

		log.Infof("Command successful:\n%s", out)
	}

	return nil
}

// EndpointJoin sets up the endpoint working directory.
func (d *Daemon) EndpointJoin(ep types.Endpoint) error {
	lxcDir := filepath.Join(".", strconv.Itoa(int(ep.ID)))

	if err := os.MkdirAll(lxcDir, 0777); err != nil {
		log.Warningf("Failed to create container temporary directory: %s", err)
		return fmt.Errorf("failed to create temporary directory: %s", err)
	}

	d.conf.OptsMU.RLock()
	ep.SetDefaultOpts(d.conf.Opts)
	d.conf.OptsMU.RUnlock()

	d.InsertEndpoint(&ep)

	return nil
}

// EndpointLeave cleans the directory used by the endpoint epID and all relevant details
// with the epID.
func (d *Daemon) EndpointLeave(epID uint16) error {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	ep := d.lookupCiliumEndpoint(epID)
	if ep == nil {
		return fmt.Errorf("endpoint %d not found", epID)
	}

	lxcDir := filepath.Join(".", strconv.Itoa(int(ep.ID)))
	os.RemoveAll(lxcDir)

	if err := d.conf.LXCMap.DeleteElement(ep); err != nil {
		log.Warningf("Unable to remove endpoint from map: %s", err)
	}

	args := []string{d.conf.LibDir, strconv.Itoa(int(epID))}
	out, err := exec.Command(filepath.Join(d.conf.LibDir, "leave_ep.sh"), args...).CombinedOutput()
	if err != nil {
		log.Warningf("Command execution failed: %s", err)
		log.Warningf("Command output:\n%s", out)
		ep.LogStatus(types.Failure, fmt.Sprintf("error: \"%s\" command output: \"%s\"", err, out))
		return fmt.Errorf("error: \"%s\"\noutput: \"%s\"", err, out)
	}

	if ep.Consumable != nil {
		ep.Consumable.RemoveMap(ep.PolicyMap)
	}

	// Remove policy BPF map
	if err := os.RemoveAll(ep.PolicyMapPath()); err != nil {
		log.Warningf("Unable to remove policy map file (%s): %s", ep.PolicyMapPath(), err)
	}

	// Remove IPv6 connection tracking map
	if err := os.RemoveAll(ep.Ct6MapPath()); err != nil {
		log.Warningf("Unable to remove IPv6 CT map file (%s): %s", ep.Ct6MapPath(), err)
	}

	// Remove IPv4 connection tracking map
	if err := os.RemoveAll(ep.Ct4MapPath()); err != nil {
		log.Warningf("Unable to remove IPv4 CT map file (%s): %s", ep.Ct4MapPath(), err)
	}

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
	origDir := filepath.Join(".", strconv.Itoa(int(ep.ID)))
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

		return fmt.Errorf("Restored original endpoint directory, atomic replace failed: %s", err)
	}

	os.RemoveAll(backupDir)
	log.Infof("Successfully regenerated program for endpoint %s", ep.String())

	return nil
}

// EndpointUpdate updates the given endpoint and recompiles the bpf map.
func (d *Daemon) EndpointUpdate(epID uint16, opts types.OptionMap) error {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	if ep := d.lookupCiliumEndpoint(epID); ep != nil {
		if err := ep.Opts.Validate(opts); err != nil {
			return err
		}

		if opts != nil && !ep.ApplyOpts(opts) {
			// No changes have been applied, skip update
			return nil
		}

		if val, ok := opts[types.OptionLearnTraffic]; ok {
			ll := types.NewLearningLabel(ep.ID, val)
			d.endpointsLearningRegister <- *ll
		}

		err := d.regenerateEndpoint(ep)
		if err != nil {
			ep.LogStatus(types.Failure, err.Error())
		} else {
			ep.LogStatusOK("Successfully regenerated endpoint")
		}
		return err
	} else {
		return fmt.Errorf("endpoint %d not found", epID)
	}
}

// EndpointSave saves the endpoint in the daemon internal endpoint map.
func (d *Daemon) EndpointSave(ep types.Endpoint) error {
	d.InsertEndpoint(&ep)
	return nil
}

func (d *Daemon) EndpointLabelsGet(epID uint16) (*types.OpLabels, error) {
	d.containersMU.RLock()
	defer d.containersMU.RUnlock()
	d.endpointsMU.RLock()
	defer d.endpointsMU.RUnlock()

	ep := d.lookupCiliumEndpoint(epID)
	if ep == nil {
		return nil, fmt.Errorf("endpoint %d not found", epID)
	}

	cont := d.containers[ep.DockerID]
	if cont == nil {
		return nil, fmt.Errorf("container %s not found in cache", ep.DockerID)
	}

	return cont.OpLabels.DeepCopy(), nil
}

func (d *Daemon) EndpointLabelsUpdate(epID uint16, labelOps types.LabelOp) error {
	ep, err := d.EndpointGet(epID)
	if err != nil {
		return err
	}
	if ep == nil {
		return fmt.Errorf("Endpoint %d not found", epID)
	}

	d.conf.ValidLabelPrefixesMU.RLock()
	for k, v := range labelOps {
		labelOps[k] = d.conf.ValidLabelPrefixes.FilterLabels(v)
	}
	d.conf.ValidLabelPrefixesMU.RUnlock()

	d.containersMU.Lock()
	cont := d.containers[ep.DockerID]
	if cont == nil {
		d.containersMU.Unlock()
		return fmt.Errorf("container not found on cache")
	}

	update := false

	if labels, ok := labelOps[types.AddLabelsOp]; ok {
		cont.OpLabels.AllLabels.MergeLabels(labels)
		for k, v := range labels {
			if cont.OpLabels.ProbeLabels[k] == nil {
				cont.OpLabels.UserLabels[k] = v
			}
		}
	}

	if labels, ok := labelOps[types.DelLabelsOp]; ok {
		for k := range labels {
			delete(cont.OpLabels.UserLabels, k)
			if ep.SecLabel != nil && ep.SecLabel.Labels[k] != nil {
				delete(ep.SecLabel.Labels, k)
				update = true
			}
		}
	}

	if labels, ok := labelOps[types.EnableLabelsOp]; ok {
		for k, v := range labels {
			if cont.OpLabels.UserLabels[k] == nil && cont.OpLabels.ProbeLabels[k] == nil {
				d.containersMU.Unlock()
				return fmt.Errorf("label %s not found, please add it first in order to enable it", v)
			}
		}
		update = true
		if ep.SecLabel == nil {
			ep.SecLabel.Labels = labels
		} else {
			ep.SecLabel.Labels.MergeLabels(labels)
		}
	}

	if labels, ok := labelOps[types.DisableLabelsOp]; ok {
		for k := range labels {
			if ep.SecLabel != nil && ep.SecLabel.Labels[k] != nil {
				delete(ep.SecLabel.Labels, k)
				update = true
			}
		}
	}

	if update {
		if ep.SecLabel != nil {
			if isNewContainer, container, err := d.updateUserLabels(ep.DockerID, ep.SecLabel.Labels); err != nil {
				d.containersMU.Unlock()
				return err
			} else {
				d.containersMU.Unlock()
				return d.updateContainer(container, isNewContainer)
			}
		}
	}

	d.containersMU.Unlock()
	return nil
}
