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

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/workloads"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// SyncState syncs cilium state against the containers running in the host. dir is the
// cilium's running directory. If clean is set, the endpoints that don't have its
// container in running state are deleted.
func (d *Daemon) SyncState(dir string, clean bool) error {

	log.Info("Restoring endpoints from former life...")

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

	nEndpoints := len(possibleEPs)

	// we need to signalize when the endpoints are restored, i.e., when the
	// essential attributes were populated on the daemon, such as: IPs allocated
	// and endpoint default options.
	epRestored := make(chan bool, nEndpoints)
	// we need to signalize when the endpoints are regenerated, i.e., when
	// they have finished to rebuild after being restored.
	epRegenerated := make(chan bool, nEndpoints)

	for _, ep := range possibleEPs {
		go func(ep *endpoint.Endpoint, epRestored, epRegenerated chan<- bool) {
			scopedLog := log.WithField(logfields.EndpointID, ep.ID)
			skipRestore := false
			if _, err := netlink.LinkByName(ep.IfName); err != nil {
				scopedLog.Infof("Interface %s could not be found for endpoint being restored, ignoring", ep.IfName)
				skipRestore = true
			} else if !workloads.IsRunning(ep) {
				scopedLog.Info("No workload could be associated with endpoint being restored, ignoring")
				skipRestore = true
			}

			if clean && skipRestore {
				d.deleteEndpointQuiet(ep)
				epRegenerated <- false
				epRestored <- false
				return
			}

			ep.Mutex.Lock()
			scopedLog.Debug("Restoring endpoint")
			ep.LogStatusOKLocked(endpoint.Other, "Restoring endpoint from previous cilium instance")

			if err := d.allocateIPsLocked(ep); err != nil {
				ep.Mutex.Unlock()
				scopedLog.WithError(err).Error("Failed to re-allocate IP of endpoint. Not restoring endpoint.")
				d.deleteEndpointQuiet(ep)
				epRegenerated <- false
				epRestored <- false
				return
			}

			if option.Config.KeepConfig {
				ep.SetDefaultOpts(nil)
			} else {
				ep.SetDefaultOpts(option.Config.Opts)
				alwaysEnforce := policy.GetPolicyEnabled() == option.AlwaysEnforce
				ep.Opts.Set(option.IngressPolicy, alwaysEnforce)
				ep.Opts.Set(option.EgressPolicy, alwaysEnforce)
			}

			endpointmanager.Insert(ep)
			epRestored <- true

			ep.LogStatusOKLocked(endpoint.Other, "Synchronizing endpoint labels with KVStore")
			if err := d.syncLabels(ep); err != nil {
				scopedLog.WithError(err).Warn("Unable to restore endpoint")
				ep.Mutex.Unlock()
				epRegenerated <- false
				return
			}
			ready := ep.SetStateLocked(endpoint.StateWaitingToRegenerate, "Triggering synchronous endpoint regeneration while syncing state to host")
			ep.Mutex.Unlock()

			if !ready {
				scopedLog.WithField(logfields.EndpointState, ep.GetState()).Warn("Endpoint in inconsistent state")
				epRegenerated <- false
				return
			}
			if buildSuccess := <-ep.Regenerate(d, "syncing state to host"); !buildSuccess {
				scopedLog.Warn("Failed while regenerating endpoint")
				epRegenerated <- false
				return
			}

			ep.Mutex.RLock()
			scopedLog.WithField(logfields.IPAddr, []string{ep.IPv4.String(), ep.IPv6.String()}).Info("Restored endpoint")
			ep.Mutex.RUnlock()
			epRegenerated <- true
		}(ep, epRestored, epRegenerated)
	}

	go func() {
		regenerated, total := 0, 0
		if nEndpoints > 0 {
			for buildSuccess := range epRegenerated {
				if buildSuccess {
					regenerated++
				}
				total++
				if total >= nEndpoints {
					break
				}
			}
		}
		close(epRegenerated)

		log.WithFields(logrus.Fields{
			"regenerated": regenerated,
			"total":       total,
		}).Info("Finished regenerating restored endpoints")
	}()

	if nEndpoints > 0 {
		// We need to wait for the endpoints IPs and labels
		// are properly synced before continuing.
		nEPsRestored := 0
		for range epRestored {
			nEPsRestored++
			if nEPsRestored >= nEndpoints {
				break
			}
		}
		close(epRestored)

		log.WithFields(logrus.Fields{
			"count.restored": nEPsRestored,
			"count.total":    nEndpoints,
		}).Info("Endpoints restored, endpoints will continue to regenerate in background")
	}

	return nil
}

func (d *Daemon) allocateIPsLocked(ep *endpoint.Endpoint) error {
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

	if !option.Config.IPv4Disabled {
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
			scopedLog := log.WithFields(logrus.Fields{
				logfields.EndpointID: epID,
				logfields.Path:       filepath.Join(epDir, common.CHeaderFileName),
			})
			scopedLog.Debug("Reading directory")
			epFiles, err := ioutil.ReadDir(epDir)
			if err != nil {
				scopedLog.WithError(err).Warn("Error while reading directory. Ignoring it...")
				return ""
			}
			cHeaderFile := common.FindEPConfigCHeader(epDir, epFiles)
			if cHeaderFile == "" {
				return ""
			}
			return cHeaderFile
		}
		// There's an odd issue where the first read dir doesn't work.
		cHeaderFile := readDir()
		if cHeaderFile == "" {
			cHeaderFile = readDir()
		}

		scopedLog := log.WithFields(logrus.Fields{
			logfields.EndpointID: epID,
			logfields.Path:       cHeaderFile,
		})

		if cHeaderFile == "" {
			scopedLog.Info("C header file not found. Ignoring endpoint")
			continue
		}

		scopedLog.Debug("Found endpoint C header file")

		strEp, err := common.GetCiliumVersionString(cHeaderFile)
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to read the C header file")
			continue
		}
		ep, err := endpoint.ParseEndpoint(strEp)
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to parse the C header file")
			continue
		}
		possibleEPs = append(possibleEPs, ep)
	}
	return possibleEPs
}

// syncLabels syncs the labels from the labels' database for the given endpoint.
// To be used with endpoint.Mutex locked.
func (d *Daemon) syncLabels(ep *endpoint.Endpoint) error {
	// Filter the restored labels with the new daemon's filter
	l, _ := labels.FilterLabels(ep.OpLabels.IdentityLabels())
	identity, _, err := identityPkg.AllocateIdentity(l)
	if err != nil {
		return err
	}

	if ep.SecurityIdentity != nil {
		if oldSecID := ep.SecurityIdentity.ID; identity.ID != oldSecID {
			log.WithFields(logrus.Fields{
				logfields.EndpointID:              ep.ID,
				logfields.IdentityLabels + ".old": oldSecID,
				logfields.IdentityLabels + ".new": identity.ID,
			}).Info("Security label ID for endpoint is different that the one stored, updating")
		}
	}

	ep.SetIdentity(identity)

	return nil
}
