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
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/workloads/containerd"

	log "github.com/sirupsen/logrus"
)

// deleteNonFunctionalEndpoints cleans all endpoints that do not have a running
// container associated with it.
func (d *Daemon) deleteNonFunctionalEndpoints() {
	for _, ep := range endpointmanager.Endpoints {
		if !containerd.IsRunning(ep) {
			log.WithFields(log.Fields{
				logfields.EndpointID: ep.StringID(),
			}).Info("No workload could be associated with endpoint, removing endpoint")
			d.deleteEndpoint(ep)
		}
	}
}

// SyncState syncs cilium state against the containers running in the host. dir is the
// cilium's running directory. If clean is set, the endpoints that don't have its
// container in running state are deleted.
func (d *Daemon) SyncState(dir string, clean bool) error {
	restored := 0

	log.Info("Restoring old cilium endpoints...")

	dirFiles, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}
	eptsID := endpoint.FilterEPDir(dirFiles)

	possibleEPs := readEPsFromDirNames(dir, eptsID)

	if len(possibleEPs) == 0 {
		log.Info("No old endpoints found.")
		return nil
	}

	for _, ep := range possibleEPs {
		log.WithField(logfields.EndpointID, ep.ID).Debug("Restoring endpoint")

		if err := d.syncLabels(ep); err != nil {
			log.WithError(err).WithField(logfields.EndpointID, ep.ID).Warn("Unable to restore endpoint")
			continue
		}

		ep.Mutex.Lock()
		if d.conf.KeepConfig {
			ep.SetDefaultOpts(nil)
		} else {
			ep.SetDefaultOpts(d.conf.Opts)
			alwaysEnforce := policy.GetPolicyEnabled() == endpoint.AlwaysEnforce
			ep.Opts.Set(endpoint.OptionPolicy, alwaysEnforce)
		}

		endpointmanager.Insert(ep)
		restored++

		ep.Mutex.Unlock()
	}

	if clean {
		d.deleteNonFunctionalEndpoints()
	}

	endpointmanager.Mutex.Lock()
	nEndpoints := len(endpointmanager.Endpoints)
	wg := make(chan bool, nEndpoints)
	for k := range endpointmanager.Endpoints {
		ep := endpointmanager.Endpoints[k]
		go func(ep *endpoint.Endpoint, wg chan<- bool) {
			scopedLog := log.WithField(logfields.EndpointID, ep.ID)
			if err := d.allocateIPs(ep); err != nil {
				scopedLog.WithError(err).Error("Failed to re-allocate IP of endpoint. Not restoring endpoint.")
				d.deleteEndpoint(ep)
				wg <- false
				return
			}

			if buildSuccess := <-ep.Regenerate(d); !buildSuccess {
				scopedLog.Warn("Failed while regenerating endpoint")
				wg <- false
				return
			}
			ep.Mutex.RLock()
			log.WithField(logfields.IPAddr, []string{ep.IPv4.String(), ep.IPv6.String()}).Info("Restored endpoint with IPs")
			ep.Mutex.RUnlock()
			wg <- true
		}(ep, wg)
	}
	endpointmanager.Mutex.Unlock()

	restored, total := 0, 0
	if nEndpoints > 0 {
		for buildSuccess := range wg {
			if buildSuccess {
				restored++
			}
			total++
			if total >= nEndpoints {
				break
			}
		}
	}
	close(wg)

	log.WithFields(log.Fields{
		"count.restored": restored,
		"count.total":    total,
	}).Info("Found endpoints of which some were restored")

	return nil
}

func (d *Daemon) allocateIPs(ep *endpoint.Endpoint) error {
	ep.Mutex.RLock()
	defer ep.Mutex.RUnlock()
	err := ipam.AllocateIP(ep.IPv6.IP())
	if err != nil {
		// TODO if allocation failed reallocate a new IP address and setup veth
		// pair accordingly
		return fmt.Errorf("unable to reallocate IPv6 address: %s", err)
	}

	defer func(ep *endpoint.Endpoint) {
		if err != nil {
			ipam.ReleaseIP(ep.IPv6.IP())
		}
	}(ep)

	if !d.conf.IPv4Disabled {
		if ep.IPv4 != nil {
			if err = ipam.AllocateIP(ep.IPv4.IP()); err != nil {
				return fmt.Errorf("unable to reallocate IPv4 address: %s", err)
			}
		}
	}
	return nil
}

// readEPsFromDirNames returns a list of endpoints from a list of directory
// names that can possible contain an endpoint.
func readEPsFromDirNames(basePath string, eptsDirNames []string) []*endpoint.Endpoint {
	possibleEPs := []*endpoint.Endpoint{}
	for _, epID := range eptsDirNames {
		epDir := filepath.Join(basePath, epID)
		readDir := func() string {
			scopedLog := log.WithFields(log.Fields{
				logfields.EndpointID: epID,
				logfields.Path:       filepath.Join(epDir, common.CHeaderFileName),
			})
			scopedLog.Debug("Reading directory")
			epFiles, err := ioutil.ReadDir(epDir)
			if err != nil {
				scopedLog.Warn("Error while reading directory. Ignoring it...")
				return ""
			}
			cHeaderFile := common.FindEPConfigCHeader(epDir, epFiles)
			if cHeaderFile == "" {
				scopedLog.Info("File not found. Ignoring endpoint.")
				return ""
			}
			return cHeaderFile
		}
		// There's an odd issue where the first read dir doesn't work.
		cHeaderFile := readDir()
		if cHeaderFile == "" {
			cHeaderFile = readDir()
		}

		scopedLog := log.WithFields(log.Fields{
			logfields.EndpointID: epID,
			logfields.Path:       cHeaderFile,
		})
		scopedLog.Debug("Found endpoint C header file")

		strEp, err := common.GetCiliumVersionString(cHeaderFile)
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to read the C header file")
			continue
		}
		ep, err := endpoint.ParseEndpoint(strEp)
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to read the C header file")
			continue
		}
		possibleEPs = append(possibleEPs, ep)
	}
	return possibleEPs
}

// syncLabels syncs the labels from the labels' database for the given endpoint.
// To be used with endpoint.Mutex locked.
func (d *Daemon) syncLabels(ep *endpoint.Endpoint) error {
	if ep.SecLabel == nil {
		return fmt.Errorf("Endpoint doesn't have a security label.")
	}

	// Filter the restored labels with the new daemon's filter
	idtyLbls, _ := labels.FilterLabels(ep.SecLabel.Labels)

	ep.SecLabel.Labels = idtyLbls

	sha256sum := ep.SecLabel.Labels.SHA256Sum()
	labels, err := LookupIdentityBySHA256(sha256sum)
	if err != nil {
		return fmt.Errorf("Unable to get labels of sha256sum:%s: %+v\n", sha256sum, err)
	}

	if labels == nil {
		l, _, err := d.CreateOrUpdateIdentity(ep.SecLabel.Labels, ep.StringID())
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
		log.WithFields(log.Fields{
			logfields.EndpointID:              ep.ID,
			logfields.IdentityLabels + ".old": ep.SecLabel.ID,
			logfields.IdentityLabels + ".new": labels.ID,
		}).Info("Security label ID for endpoint is different that the one stored, updating")
	}
	ep.SetIdentity(d, labels)

	return nil
}
