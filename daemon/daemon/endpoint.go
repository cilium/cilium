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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/cilium/cilium/common/ipam"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
)

func (d *Daemon) lookupCiliumEndpoint(id uint16) *endpoint.Endpoint {
	if ep, ok := d.endpoints[id]; ok {
		return ep
	} else {
		return nil
	}
}

func (d *Daemon) lookupDockerEndpoint(id string) *endpoint.Endpoint {
	if ep, ok := d.endpointsDockerEP[id]; ok {
		return ep
	} else {
		return nil
	}
}

func (d *Daemon) lookupDockerID(id string) *endpoint.Endpoint {
	if ep, ok := d.endpointsDocker[id]; ok {
		return ep
	} else {
		return nil
	}
}

// Public API to insert an endpoint without connecting it to a container
func (d *Daemon) InsertEndpoint(ep *endpoint.Endpoint) {
	d.endpointsMU.Lock()
	d.insertEndpoint(ep)
	d.endpointsMU.Unlock()
}

// insertEndpoint inserts the ep in the endpoints map. To be used with endpointsMU locked.
func (d *Daemon) insertEndpoint(ep *endpoint.Endpoint) {
	if ep.Status == nil {
		ep.Status = &endpoint.EndpointStatus{}
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
func (d *Daemon) setEndpointSecLabel(endpointID *uint16, dockerID, dockerEPID string, labels *policy.Identity) uint16 {
	var (
		ep *endpoint.Endpoint
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
		return 0
	}

	if !ok {
		return 0
	}

	log.Debugf("Setting labels of %d: %+v", ep.ID, labels)

	setIfNotEmpty(&ep.DockerID, dockerID)
	setIfNotEmpty(&ep.DockerEndpointID, dockerEPID)
	setIfNotEmptyUint16(&ep.ID, endpointID)

	ep.SetIdentity(d, labels)
	// Update all IDs in respective MAPs
	d.insertEndpoint(ep)
	return ep.ID
}

// EndpointGetByDockerID returns a copy of the endpoint for the given dockerEPID, or nil
// if the endpoint was not found.
func (d *Daemon) EndpointGetByDockerID(dockerID string) (*endpoint.Endpoint, error) {
	d.endpointsMU.RLock()
	defer d.endpointsMU.RUnlock()

	if ep := d.lookupDockerID(dockerID); ep != nil {
		return ep.DeepCopy(), nil
	}
	return nil, nil
}

// EndpointGetByDockerEPID returns a copy of the endpoint for the given dockerEPID, or nil
// if the endpoint was not found.
func (d *Daemon) EndpointGetByDockerEPID(dockerEPID string) (*endpoint.Endpoint, error) {
	d.endpointsMU.RLock()
	defer d.endpointsMU.RUnlock()

	if ep := d.lookupDockerEndpoint(dockerEPID); ep != nil {
		return ep.DeepCopy(), nil
	}
	return nil, nil
}

// EndpointGet returns a copy of the endpoint for the given endpointID, or nil if the
// endpoint was not found.
func (d *Daemon) EndpointGet(endpointID uint16) (*endpoint.Endpoint, error) {
	d.endpointsMU.RLock()
	defer d.endpointsMU.RUnlock()

	if ep := d.lookupCiliumEndpoint(endpointID); ep != nil {
		return ep.DeepCopy(), nil
	}

	return nil, nil
}

// EndpointsGet returns a copy of all the endpoints or nil if there are no endpoints.
func (d *Daemon) EndpointsGet() ([]endpoint.Endpoint, error) {
	d.endpointsMU.RLock()
	defer d.endpointsMU.RUnlock()

	eps := []endpoint.Endpoint{}
	epsSet := map[*endpoint.Endpoint]bool{}
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

func (d *Daemon) createBPFMAPs(epID uint16) error {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()
	ep, ok := d.endpoints[epID]
	if !ok {
		return fmt.Errorf("endpoint %d not found", epID)
	}

	return ep.Regenerate(d)
}

// EndpointJoin sets up the endpoint working directory.
func (d *Daemon) EndpointJoin(ep endpoint.Endpoint) error {
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

	ep.Leave(d)

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
		ep.LogStatus(endpoint.Failure, fmt.Sprintf("error: \"%s\" command output: \"%s\"", err, out))
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

	var ipamType ipam.IPAMType
	if ep.IsCNI() {
		ipamType = ipam.CNIIPAMType
	} else {
		ipamType = ipam.LibnetworkIPAMType
	}

	if d.conf.IPv4Enabled {
		ipv4 := ep.IPv4.IP()
		if err := d.ReleaseIP(ipamType, ipam.IPAMReq{IP: &ipv4}); err != nil {
			log.Warningf("error while releasing IPv4 %s: %s", ep.IPv4.IP(), err)
		}
	}
	ipv6 := ep.IPv6.IP()
	if err := d.ReleaseIP(ipamType, ipam.IPAMReq{IP: &ipv6}); err != nil {
		log.Warningf("error while releasing IPv6 %s: %s", ep.IPv6.IP(), err)
	}

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

// EndpointUpdate updates the given endpoint and recompiles the bpf map.
func (d *Daemon) EndpointUpdate(epID uint16, opts option.OptionMap) error {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	if ep := d.lookupCiliumEndpoint(epID); ep != nil {
		d.invalidateCache()
		err := ep.Update(d, opts)
		if err == nil {
			if val, ok := opts[endpoint.OptionLearnTraffic]; ok {
				ll := labels.NewLearningLabel(ep.ID, val)
				d.endpointsLearningRegister <- *ll
			}
		}
		return err
	}

	return fmt.Errorf("endpoint %d not found", epID)
}

// EndpointSave saves the endpoint in the daemon internal endpoint map.
func (d *Daemon) EndpointSave(ep endpoint.Endpoint) error {
	d.InsertEndpoint(&ep)
	return nil
}

func (d *Daemon) EndpointLabelsGet(epID uint16) (*labels.OpLabels, error) {
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

func (d *Daemon) EndpointLabelsUpdate(epID uint16, labelOps labels.LabelOp) error {
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

	if labels, ok := labelOps[labels.AddLabelsOp]; ok {
		cont.OpLabels.AllLabels.MergeLabels(labels)
		for k, v := range labels {
			if cont.OpLabels.ProbeLabels[k] == nil {
				cont.OpLabels.UserLabels[k] = v
			}
		}
	}

	if labels, ok := labelOps[labels.DelLabelsOp]; ok {
		for k := range labels {
			delete(cont.OpLabels.UserLabels, k)
			if ep.SecLabel != nil && ep.SecLabel.Labels[k] != nil {
				delete(ep.SecLabel.Labels, k)
				update = true
			}
		}
	}

	if labels, ok := labelOps[labels.EnableLabelsOp]; ok {
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

	if labels, ok := labelOps[labels.DisableLabelsOp]; ok {
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
