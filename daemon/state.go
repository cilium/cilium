// Copyright 2016-2018 Authors of Cilium
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
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/workloads"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type endpointRestoreState struct {
	restored []*endpoint.Endpoint
	toClean  []*endpoint.Endpoint
}

// restoreOldEndpoints reads the list of existing endpoints previously managed
// Cilium when it was last run and associated it with container workloads. This
// function performs the first step in restoring the endpoint structure,
// allocating their existing IP out of the CIDR block and then inserting the
// endpoints into the endpoints list. It needs to be followed by a call to
// regenerateRestoredEndpoints() once the endpoint builder is ready.
//
// If clean is true, endpoints which cannot be associated with a container
// workloads are deleted.
func (d *Daemon) restoreOldEndpoints(dir string, clean bool) (*endpointRestoreState, error) {
	state := &endpointRestoreState{
		restored: []*endpoint.Endpoint{},
		toClean:  []*endpoint.Endpoint{},
	}

	if !option.Config.RestoreState {
		log.Info("Endpoint restore is disabled, skipping restore step")
		return state, nil
	}

	log.Info("Restoring endpoints from former life...")

	existingEndpoints, err := lxcmap.DumpToMap()
	if err != nil {
		return state, err
	}

	dirFiles, err := ioutil.ReadDir(dir)
	if err != nil {
		return state, err
	}
	eptsID := endpoint.FilterEPDir(dirFiles)

	possibleEPs := readEPsFromDirNames(dir, eptsID)

	if len(possibleEPs) == 0 {
		log.Info("No old endpoints found.")
		return state, nil
	}

	for _, ep := range possibleEPs {
		scopedLog := log.WithField(logfields.EndpointID, ep.ID)
		skipRestore := false

		// On each restart, the health endpoint is supposed to be recreated.
		// Hence we need to clean health endpoint state unconditionally.
		if ep.HasLabels(labels.LabelHealth) {
			skipRestore = true
		} else {
			if _, err := netlink.LinkByName(ep.IfName); err != nil {
				scopedLog.Infof("Interface %s could not be found for endpoint being restored, ignoring", ep.IfName)
				skipRestore = true
			} else if !workloads.IsRunning(ep) {
				scopedLog.Info("No workload could be associated with endpoint being restored, ignoring")
				skipRestore = true
			}
		}

		if clean && skipRestore {
			state.toClean = append(state.toClean, ep)
			continue
		}

		ep.UnconditionalLock()
		scopedLog.Debug("Restoring endpoint")
		ep.LogStatusOKLocked(endpoint.Other, "Restoring endpoint from previous cilium instance")

		if err := d.allocateIPsLocked(ep); err != nil {
			ep.Unlock()
			scopedLog.WithError(err).Error("Failed to re-allocate IP of endpoint. Not restoring endpoint.")
			state.toClean = append(state.toClean, ep)
			continue
		}

		if option.Config.KeepConfig {
			ep.SetDefaultOpts(nil)
		} else {
			ep.SetDefaultOpts(option.Config.Opts)
			alwaysEnforce := policy.GetPolicyEnabled() == option.AlwaysEnforce
			ep.SetIngressPolicyEnabledLocked(alwaysEnforce)
			ep.SetEgressPolicyEnabledLocked(alwaysEnforce)
		}

		ep.Unlock()

		ep.SkipStateClean()

		state.restored = append(state.restored, ep)

		delete(existingEndpoints, ep.IPv4.String())
		delete(existingEndpoints, ep.IPv6.String())
	}

	log.WithFields(logrus.Fields{
		"count.restored": len(state.restored),
		"count.total":    len(possibleEPs),
	}).Info("Endpoints restored")

	for hostIP, info := range existingEndpoints {
		if ip := net.ParseIP(hostIP); !info.IsHost() && ip != nil {
			if err := lxcmap.DeleteEntry(ip); err != nil {
				log.WithError(err).Warn("Unable to delete obsolete endpoint from BPF map")
			} else {
				log.Debugf("Removed outdated endpoint %d from endpoint map", info.LxcID)
			}
		}
	}

	return state, nil
}

func (d *Daemon) regenerateRestoredEndpoints(state *endpointRestoreState) {
	log.Infof("Regenerating %d restored endpoints", len(state.restored))

	// Before regenerating, check whether the CT map has properties that
	// match this Cilium userspace instance. If not, it must be removed
	ctmap.DeleteIfUpgradeNeeded(nil)

	// we need to signalize when the endpoints are regenerated, i.e., when
	// they have finished to rebuild after being restored.
	epRegenerated := make(chan bool, len(state.restored))

	// Insert all endpoints into the endpoint list first before starting
	// the regeneration. This is required to ensure that if an individual
	// regeneration causes an identity change of an endpoint, the new
	// identity will trigger a policy recalculation of all endpoints to
	// account for the new identity during the grace period. For this
	// purpose, all endpoints being restored must already be in the
	// endpoint list.
	for i, ep := range state.restored {
		// If the endpoint has local conntrack option enabled, then
		// check whether the CT map needs upgrading (and do so).
		if ep.Options.IsEnabled(option.ConntrackLocal) {
			ctmap.DeleteIfUpgradeNeeded(ep)
		}

		// Insert into endpoint manager so it can be regenerated when calls to
		// RegenerateAllEndpoints() are made. This must be done synchronously (i.e.,
		// not in a goroutine) because regenerateRestoredEndpoints must guarantee
		// upon returning that endpoints are exposed to other subsystems via
		// endpointmanager.

		if err := endpointmanager.Insert(ep); err != nil {
			log.WithError(err).Warning("Unable to restore endpoint")
			// remove endpoint from slice of endpoints to restore
			state.restored = append(state.restored[:i], state.restored[i+1:]...)
		}
	}

	for _, ep := range state.restored {
		go func(ep *endpoint.Endpoint, epRegenerated chan<- bool) {
			if err := ep.RLockAlive(); err != nil {
				ep.LogDisconnectedMutexAction(err, "before filtering labels during regenerating restored endpoint")
				return
			}
			scopedLog := log.WithField(logfields.EndpointID, ep.ID)
			// Filter the restored labels with the new daemon's filter
			l, _ := labels.FilterLabels(ep.OpLabels.IdentityLabels())
			ep.RUnlock()

			identity, _, err := identityPkg.AllocateIdentity(l)
			if err != nil {
				scopedLog.WithError(err).Warn("Unable to restore endpoint")
				epRegenerated <- false
			}
			// Wait for initial identities from the kvstore before
			// doing any policy calculation for endpoints that don't have
			// a fixed identity or are not well known.
			if !identity.IsFixed() && !identity.IsWellKnown() {
				identityPkg.WaitForInitialIdentities()
			}

			if err := ep.LockAlive(); err != nil {
				scopedLog.Warn("Endpoint to restore has been deleted")
				return
			}

			ep.LogStatusOKLocked(endpoint.Other, "Synchronizing endpoint labels with KVStore")

			if ep.SecurityIdentity != nil {
				if oldSecID := ep.SecurityIdentity.ID; identity.ID != oldSecID {
					log.WithFields(logrus.Fields{
						logfields.EndpointID:              ep.ID,
						logfields.IdentityLabels + ".old": oldSecID,
						logfields.IdentityLabels + ".new": identity.ID,
					}).Info("Security identity for endpoint is different from the security identity restored for the endpoint")

					// The identity of the endpoint being
					// restored has changed. This can be
					// caused by two main reasons:
					//
					// 1) Cilium has been upgraded,
					// downgraded or the configuration has
					// changed and the new version or
					// configuration causes different
					// labels to be considered security
					// relevant for this endpoint.
					//
					// Immediately using the identity may
					// cause connectivity problems if this
					// is the first endpoint in the cluster
					// to use the new identity. All other
					// nodes will not have had a chance to
					// adjust the security policies for
					// their endpoints. Hence, apply a
					// grace period to allow for the
					// update. It is not required to check
					// any local endpoints for potential
					// outdated security rules, the
					// notification of the new security
					// identity will have been received and
					// will trigger the necessary
					// recalculation of all local
					// endpoints.
					//
					// 2) The identity is outdated as the
					// state in the kvstore has changed.
					// This reason would justify an
					// immediate use of the new identity
					// but given the current identity is
					// already in place, it is also correct
					// to continue using it for the
					// duration of a grace period.
					time.Sleep(defaults.IdentityChangeGracePeriod)
				}
			}
			ep.SetIdentity(identity)

			ready := ep.SetStateLocked(endpoint.StateWaitingToRegenerate, "Triggering synchronous endpoint regeneration while syncing state to host")
			ep.Unlock()

			if !ready {
				scopedLog.WithField(logfields.EndpointState, ep.GetState()).Warn("Endpoint in inconsistent state")
				epRegenerated <- false
				return
			}
			regenContext := endpoint.NewRegenerationContext(
				"syncing state to host")
			if buildSuccess := <-ep.Regenerate(d, regenContext); !buildSuccess {
				scopedLog.Warn("Failed while regenerating endpoint")
				epRegenerated <- false
				return
			}

			// NOTE: UnconditionalRLock is used here because it's used only for logging an already restored endpoint
			ep.UnconditionalRLock()
			scopedLog.WithField(logfields.IPAddr, []string{ep.IPv4.String(), ep.IPv6.String()}).Info("Restored endpoint")
			ep.RUnlock()
			epRegenerated <- true
		}(ep, epRegenerated)
	}

	for _, ep := range state.toClean {
		go d.deleteEndpointQuiet(ep, true)
	}

	go func() {
		regenerated, total := 0, 0
		if len(state.restored) > 0 {
			for buildSuccess := range epRegenerated {
				if buildSuccess {
					regenerated++
				}
				total++
				if total >= len(state.restored) {
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

// readEPsFromDirNames returns a mapping of endpoint ID to endpoint of endpoints
// from a list of directory names that can possible contain an endpoint.
func readEPsFromDirNames(basePath string, eptsDirNames []string) map[uint16]*endpoint.Endpoint {
	possibleEPs := map[uint16]*endpoint.Endpoint{}
	for _, epDirName := range eptsDirNames {
		epDir := filepath.Join(basePath, epDirName)
		readDir := func() string {
			scopedLog := log.WithFields(logrus.Fields{
				logfields.EndpointID: epDirName,
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
			logfields.EndpointID: epDirName,
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
		if _, ok := possibleEPs[ep.ID]; ok {
			// If the endpoint already exists then give priority to the directory
			// that contains an endpoint that didn't fail to be build.
			if strings.HasSuffix(ep.DirectoryPath(), epDirName) {
				possibleEPs[ep.ID] = ep
			}
		} else {
			possibleEPs[ep.ID] = ep
		}
	}
	return possibleEPs
}
