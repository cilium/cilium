// Copyright 2016-2017 Authors of Cilium
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

package main

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/events"

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
	defer d.endpointsMU.Unlock()

	dirFiles, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}
	eptsID := endpoint.FilterEPDir(dirFiles)

	possibleEPs := readEPsFromDirNames(dir, eptsID)

	if len(possibleEPs) == 0 {
		log.Debug("No old endpoints found.")
		return nil
	}

	for _, ep := range possibleEPs {
		log.Debugf("Restoring endpoint ID %d", ep.ID)

		if err := d.syncLabels(ep); err != nil {
			log.Warningf("Unable to restore endpoint %+v: %s", ep, err)
			continue
		}

		if d.conf.KeepConfig {
			ep.SetDefaultOpts(nil)
		} else {
			ep.SetDefaultOpts(d.conf.Opts)
		}

		if err := ep.Regenerate(d); err != nil {
			log.Warningf("Unable to restore endpoint %+v: %s", ep, err)
			continue
		}

		d.insertEndpoint(ep)
		restored++

		log.Infof("Restored endpoint: %d", ep.ID)
	}

	log.Infof("Restored %d endpoints", restored)

	if clean {
		d.cleanUpDockerDandlingEndpoints()
	}

	for k := range d.endpoints {
		ep := d.endpoints[k]
		if err := d.allocateIPs(ep); err != nil {
			log.Errorf("Failed while reallocating ep %d's IP addresses: %s. Endpoint won't be restored", ep.ID, err)
			d.DeleteEndpointLocked(ep)
			continue
		}

		log.Infof("EP %d's IP addresses successfully reallocated", ep.ID)
		err = ep.Regenerate(d)
		if err != nil {
			log.Warningf("Failed while regenerating endpoint %d: %s", ep.ID, err)
		} else {
			if ep.SecLabel != nil {
				d.events <- *events.NewEvent(events.IdentityAdd, ep.SecLabel.DeepCopy())
			}
			log.Infof("Restored endpoint %d", ep.ID)
		}
	}

	return nil
}

func (d *Daemon) allocateIPs(ep *endpoint.Endpoint) error {
	err := d.AllocateIP(ep.IPv6.IP())
	if err != nil {
		// TODO if allocation failed reallocate a new IP address and setup veth
		// pair accordingly
		return fmt.Errorf("unable to reallocate IPv6 address: %s", err)
	}

	defer func(ep *endpoint.Endpoint) {
		if err != nil {
			d.ReleaseIP(ep.IPv6.IP())
		}
	}(ep)

	if !d.conf.IPv4Disabled {
		if ep.IPv4 != nil {
			if err = d.AllocateIP(ep.IPv4.IP()); err != nil {
				return fmt.Errorf("unable to reallocate IPv4 address: %s", err)
			}
		}
	}
	return nil
}

// readEPsFromDirNames returns a list of endpoints from a list of directory names that
// possible contain an endpoint.
func readEPsFromDirNames(basePath string, eptsDirNames []string) []*endpoint.Endpoint {
	possibleEPs := []*endpoint.Endpoint{}
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
		ep, err := endpoint.ParseEndpoint(strEp)
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
func (d *Daemon) syncLabels(ep *endpoint.Endpoint) error {
	if ep.SecLabel == nil {
		return fmt.Errorf("Endpoint doesn't have a security label.")
	}

	sha256sum := ep.SecLabel.Labels.SHA256Sum()
	labels, err := d.LookupIdentityBySHA256(sha256sum)
	if err != nil {
		return fmt.Errorf("Unable to get labels of sha256sum:%s: %+v\n", sha256sum, err)
	}

	if ep.DockerID == "" {
		return nil
	}

	if labels == nil {
		l, _, err := d.CreateOrUpdateIdentity(ep.SecLabel.Labels, ep.DockerID)
		if err != nil {
			return fmt.Errorf("Unable to put labels %+v: %s\n", ep.SecLabel.Labels, err)
		}
		labels = l
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
	ep.SetIdentity(d, labels)

	return nil
}

// cleanUpDockerDandlingEndpoints cleans all endpoints that are dandling by checking out
// if a particular endpoint has its container running.
func (d *Daemon) cleanUpDockerDandlingEndpoints() {
	cleanUp := func(ep *endpoint.Endpoint) {
		log.Infof("Endpoint %d not found in docker, cleaning up...", ep.ID)
		d.DeleteEndpointLocked(ep)
	}

	for k := range d.endpoints {
		ep := d.endpoints[k]
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
