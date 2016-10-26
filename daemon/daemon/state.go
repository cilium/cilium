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
	"io/ioutil"
	"path/filepath"
	"reflect"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/ipam"
	"github.com/cilium/cilium/common/types"

	dockerAPI "github.com/docker/engine-api/client"
	ctx "golang.org/x/net/context"
)

// SyncState syncs cilium state against the containers running in the host. dir is the
// cilium's running directory. If clean is set, the endpoints that don't have its
// container in running state are deleted.
func (d *Daemon) SyncState(dir string, clean bool) error {
	restored := 0

	log.Info("Recovering old running endpoints...")

	d.endpointsMU.Lock()
	if dir == "" {
		dir = common.CiliumPath
	}
	dirFiles, err := ioutil.ReadDir(dir)
	if err != nil {
		d.endpointsMU.Unlock()
		return err
	}
	eptsID := types.FilterEPDir(dirFiles)

	possibleEPs := readEPsFromDirNames(dir, eptsID)

	if len(possibleEPs) == 0 {
		log.Debug("No old endpoints found.")
		d.endpointsMU.Unlock()
		return nil
	}

	for _, ep := range possibleEPs {
		log.Debugf("Restoring endpoint %+v", ep)

		if err := d.syncLabels(ep); err != nil {
			log.Warningf("Unable to restore endpoint %d: %s", ep.ID, err)
			continue
		}

		if d.conf.KeepConfig {
			ep.SetDefaultOpts(nil)
		} else {
			d.conf.OptsMU.RLock()
			ep.SetDefaultOpts(d.conf.Opts)
			d.conf.OptsMU.RUnlock()
		}

		if err := d.regenerateEndpoint(ep); err != nil {
			log.Warningf("Unable to restore endpoint %d: %s", ep.ID, err)
			continue
		}

		d.insertEndpoint(ep)
		restored++

		log.Infof("Restored endpoint: %d\n", ep.ID)
	}

	d.endpointsMU.Unlock()

	log.Infof("Restored %d endpoints", restored)

	if clean {
		d.cleanUpDockerDandlingEndpoints()
	}

	eps, err := d.EndpointsGet()
	if err != nil {
		log.Warningf("Error while getting endpoints: %s", err)
	}

	for _, ep := range eps {
		if err := d.allocateIPs(&ep); err != nil {
			log.Errorf("Failed while reallocating ep %d's IP addresses: %s. Endpoint won't be restored", ep.ID, err)
			d.EndpointLeave(ep.ID)
			continue
		}
		log.Infof("EP %d's IP addresses successfully reallocated", ep.ID)
		err = d.EndpointUpdate(ep.ID, nil)
		if err != nil {
			log.Warningf("Failed while updating ep %d: %s", ep.ID, err)
		} else {
			if ep.SecLabel != nil {
				d.AddOrUpdateUINode(ep.SecLabel.ID, ep.SecLabel.Labels.ToSlice(), ep.SecLabel.RefCount())
			}
			log.Infof("EP %d completely restored", ep.ID)
		}
	}

	return nil
}

func (d *Daemon) allocateIPs(ep *types.Endpoint) error {
	allocateIP := func(ep *types.Endpoint, ipamReq ipam.IPAMReq) (resp *ipam.IPAMRep, err error) {
		if ep.IsCNI() {
			resp, err = d.AllocateIP(ipam.CNIIPAMType, ipamReq)
		} else if ep.IsLibnetwork() {
			resp, err = d.AllocateIP(ipam.LibnetworkIPAMType, ipamReq)
		}
		return
	}
	releaseIP := func(ep *types.Endpoint, ipamReq ipam.IPAMReq) (err error) {
		if ep.IsCNI() {
			err = d.ReleaseIP(ipam.CNIIPAMType, ipamReq)
		} else if ep.IsLibnetwork() {
			err = d.ReleaseIP(ipam.LibnetworkIPAMType, ipamReq)
		}
		return
	}

	_, err := allocateIP(ep, ep.IPv6.IPAMReq())
	if err != nil {
		// TODO if allocation failed reallocate a new IP address and setup veth
		// pair accordingly
		return fmt.Errorf("unable to reallocate IPv6 address: %s", err)
	} else {
		log.Infof("EP %d's IPv6 successfully reallocated", ep.ID)
	}
	defer func(ep *types.Endpoint) {
		if err != nil {
			releaseIP(ep, ep.IPv6.IPAMReq())
		}
	}(ep)

	if d.conf.IPv4Enabled {
		if ep.IPv4 != nil {
			_, err := allocateIP(ep, ep.IPv4.IPAMReq())
			if err != nil {
				return fmt.Errorf("unable to reallocate IPv4 address: %s", err)
			} else {
				log.Infof("EP %d's IPv4 successfully reallocated", ep.ID)
			}
		}
	}
	return nil
}

// readEPsFromDirNames returns a list of endpoints from a list of directory names that
// possible contain an endpoint.
func readEPsFromDirNames(basePath string, eptsDirNames []string) []*types.Endpoint {
	possibleEPs := []*types.Endpoint{}
	for _, epID := range eptsDirNames {
		epDir := filepath.Join(basePath, epID)
		readDir := func() string {
			log.Debugf("Reading directory %s\n", epDir)
			epFiles, err := ioutil.ReadDir(epDir)
			if err != nil {
				log.Warningf("Error while reading directory %q. Ignoring it...", epDir)
				return ""
			}
			cHeaderFile := common.FindEPConfigCHeader(epDir, epFiles)
			if cHeaderFile == "" {
				log.Infof("File %q not found in %q. Ignoring endpoint %s.",
					common.CHeaderFileName, epDir, epID)
				return ""
			}
			return cHeaderFile
		}
		// There's an odd issue where the first read dir doesn't work.
		cHeaderFile := readDir()
		if cHeaderFile == "" {
			cHeaderFile = readDir()
		}
		log.Debugf("Found endpoint C header file %q\n", cHeaderFile)
		strEp, err := common.GetCiliumVersionString(cHeaderFile)
		if err != nil {
			log.Warningf("Unable to read the C header file %q: %s\n", cHeaderFile, err)
			continue
		}
		ep, err := types.ParseEndpoint(strEp)
		if err != nil {
			log.Warningf("Unable to read the C header file %q: %s\n", cHeaderFile, err)
			continue
		}
		possibleEPs = append(possibleEPs, ep)
	}
	return possibleEPs
}

// syncLabels syncs the labels from the labels' database for the given endpoint. To be
// used with endpointsMU locked.
func (d *Daemon) syncLabels(ep *types.Endpoint) error {
	if ep.SecLabel == nil {
		return fmt.Errorf("Endpoint doesn't have a security label.")
	}

	sha256sum, err := ep.SecLabel.Labels.SHA256Sum()
	if err != nil {
		return fmt.Errorf("Unable to get the sha256sum of labels: %+v\n", ep.SecLabel.Labels)
	}

	labels, err := d.GetLabelsBySHA256(sha256sum)
	if err != nil {
		return fmt.Errorf("Unable to get labels of sha256sum:%s: %+v\n", sha256sum, err)
	}

	if ep.DockerID == "" {
		return nil
	}

	if labels == nil {
		labels, _, err = d.PutLabels(ep.SecLabel.Labels, ep.DockerID)
		if err != nil {
			return fmt.Errorf("Unable to put labels %+v: %s\n", ep.SecLabel.Labels, err)
		}
	}

	if !reflect.DeepEqual(labels.Labels, ep.SecLabel.Labels) {
		return fmt.Errorf("The set of labels should be the same for " +
			"the endpoint being restored and the labels stored")
	}

	if labels.ID != ep.SecLabel.ID {
		log.Infof("Security label ID for endpoint %d is different "+
			"that the one stored, updating from %d to %d\n",
			ep.ID, ep.SecLabel.ID, labels.ID)
	}
	ep.SetSecLabel(labels)

	return nil
}

// cleanUpDockerDandlingEndpoints cleans all endpoints that are dandling by checking out
// if a particular endpoint has its container running.
func (d *Daemon) cleanUpDockerDandlingEndpoints() {
	eps, _ := d.EndpointsGet()
	if eps == nil {
		return
	}

	cleanUp := func(ep types.Endpoint) {
		log.Infof("Endpoint %d not found in docker, cleaning up...", ep.ID)
		d.EndpointLeave(ep.ID)
		// FIXME: IPV4
		if ep.IPv6 != nil {
			if ep.IsCNI() {
				d.ReleaseIP(ipam.CNIIPAMType, ep.IPv6.IPAMReq())
			} else if ep.IsLibnetwork() {
				d.ReleaseIP(ipam.LibnetworkIPAMType, ep.IPv6.IPAMReq())
			}
		}

	}

	for _, ep := range eps {
		log.Debugf("Checking if endpoint is running in docker %d", ep.ID)
		if ep.DockerNetworkID != "" {
			nls, err := d.dockerClient.NetworkInspect(ctx.Background(), ep.DockerNetworkID)
			if dockerAPI.IsErrNetworkNotFound(err) {
				cleanUp(ep)
				continue
			}
			if err != nil {
				continue
			}
			found := false
			for _, v := range nls.Containers {
				if v.EndpointID == ep.DockerEndpointID {
					found = true
					break
				}
			}
			if !found {
				cleanUp(ep)
				continue
			}
		} else if ep.DockerID != "" {
			cont, err := d.dockerClient.ContainerInspect(ctx.Background(), ep.DockerID)
			if dockerAPI.IsErrContainerNotFound(err) {
				cleanUp(ep)
				continue
			}
			if err != nil {
				continue
			}
			if !cont.State.Running {
				cleanUp(ep)
				continue
			}
		} else {
			cleanUp(ep)
			continue
		}
	}
}
