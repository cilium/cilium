// Copyright 2016-2019 Authors of Cilium
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
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/connector"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/workloads"

	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type endpointRestoreState struct {
	restored []*endpoint.Endpoint
	toClean  []*endpoint.Endpoint
}

// validateEndpoint attempts to determine that the endpoint is valid, ie it
// still exists in k8s, its datapath devices are present, and Cilium is
// responsible for its workload, etc.
//
// Returns true to indicate that the endpoint is valid to restore, and an
// optional error.
func (d *Daemon) validateEndpoint(ep *endpoint.Endpoint) (valid bool, err error) {
	// On each restart, the health endpoint is supposed to be recreated.
	// Hence we need to clean health endpoint state unconditionally.
	if ep.HasLabels(labels.LabelHealth) {
		// Ignore health endpoint and don't report
		// it as not restored. But we need to clean up the old
		// state files, so do this now.
		healthStateDir := ep.StateDirectoryPath()
		scopedLog := log.WithFields(logrus.Fields{
			logfields.EndpointID: ep.ID,
			logfields.Path:       healthStateDir,
		})
		scopedLog.Debug("Removing old health endpoint state directory")
		if err := os.RemoveAll(healthStateDir); err != nil {
			scopedLog.Warning("Cannot clean up old health state directory")
		}
		return false, nil
	}

	if ep.K8sPodName != "" && ep.K8sNamespace != "" && k8s.IsEnabled() {
		_, err := k8s.Client().CoreV1().Pods(ep.K8sNamespace).Get(ep.K8sPodName, meta_v1.GetOptions{})
		if err != nil && k8serrors.IsNotFound(err) {
			return false, fmt.Errorf("kubernetes pod not found")
		}
	}

	if err := ep.ValidateConnectorPlumbing(connector.CheckLink); err != nil {
		return false, err
	}

	if option.Config.WorkloadsEnabled() && !workloads.IsRunning(ep) {
		return false, fmt.Errorf("no workload could be associated with endpoint")
	}

	if !ep.DatapathConfiguration.ExternalIPAM {
		if err := d.allocateIPsLocked(ep); err != nil {
			return false, fmt.Errorf("Failed to re-allocate IP of endpoint: %s", err)
		}
	}

	return true, nil
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
	failed := 0
	state := &endpointRestoreState{
		restored: []*endpoint.Endpoint{},
		toClean:  []*endpoint.Endpoint{},
	}

	if !option.Config.RestoreState {
		log.Info("Endpoint restore is disabled, skipping restore step")
		return state, nil
	}

	log.Info("Restoring endpoints...")

	var (
		existingEndpoints map[string]*lxcmap.EndpointInfo
		err               error
	)

	if !option.Config.DryMode {
		existingEndpoints, err = lxcmap.DumpToMap()
		if err != nil {
			log.WithError(err).Warning("Unable to open endpoint map while restoring. Skipping cleanup of endpoint map on startup")
		}
	}

	dirFiles, err := ioutil.ReadDir(dir)
	if err != nil {
		return state, err
	}
	eptsID := endpoint.FilterEPDir(dirFiles)

	possibleEPs := endpoint.ReadEPsFromDirNames(d, dir, eptsID)

	if len(possibleEPs) == 0 {
		log.Info("No old endpoints found.")
		return state, nil
	}

	for _, ep := range possibleEPs {
		scopedLog := log.WithField(logfields.EndpointID, ep.ID)
		if k8s.IsEnabled() {
			scopedLog = scopedLog.WithField("k8sPodName", ep.GetK8sNamespaceAndPodNameLocked())
		}

		restore, err := d.validateEndpoint(ep)
		if err != nil {
			scopedLog.WithError(err).Warningf("Unable to restore endpoint, ignoring")
			failed++
		}
		if !restore {
			if clean {
				state.toClean = append(state.toClean, ep)
			}
			continue
		}

		scopedLog.Debug("Restoring endpoint")
		ep.LogStatusOK(endpoint.Other, "Restoring endpoint from previous cilium instance")

		ep.SetDefaultConfiguration(true)

		ep.SkipStateClean()

		state.restored = append(state.restored, ep)

		if existingEndpoints != nil {
			delete(existingEndpoints, ep.IPv4.String())
			delete(existingEndpoints, ep.IPv6.String())
		}
	}

	log.WithFields(logrus.Fields{
		"restored": len(state.restored),
		"failed":   failed,
	}).Info("Endpoints restored")

	if existingEndpoints != nil {
		for hostIP, info := range existingEndpoints {
			if ip := net.ParseIP(hostIP); !info.IsHost() && ip != nil {
				if err := lxcmap.DeleteEntry(ip); err != nil {
					log.WithError(err).Warn("Unable to delete obsolete endpoint from BPF map")
				} else {
					log.Debugf("Removed outdated endpoint %d from endpoint map", info.LxcID)
				}
			}
		}
	}

	return state, nil
}

func (d *Daemon) regenerateRestoredEndpoints(state *endpointRestoreState) (restoreComplete chan struct{}) {
	restoreComplete = make(chan struct{}, 0)

	log.WithField("numRestored", len(state.restored)).Info("Regenerating restored endpoints")

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
	for i := len(state.restored) - 1; i >= 0; i-- {
		ep := state.restored[i]
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

		if err := ep.Expose(d.endpointManager); err != nil {
			log.WithError(err).Warning("Unable to restore endpoint")
			// remove endpoint from slice of endpoints to restore
			state.restored = append(state.restored[:i], state.restored[i+1:]...)
		}
	}

	for _, ep := range state.restored {
		go func(ep *endpoint.Endpoint, epRegenerated chan<- bool) {
			if err := ep.RegenerateAfterRestore(); err != nil {
				epRegenerated <- false
				return
			}
			epRegenerated <- true
		}(ep, epRegenerated)
	}

	var endpointCleanupCompleted sync.WaitGroup
	for _, ep := range state.toClean {
		endpointCleanupCompleted.Add(1)
		go func(ep *endpoint.Endpoint) {
			// The IP was not allocated yet so does not need to be free.
			// The identity may be allocated in the kvstore but we can't
			// release it easily as it will require to block on kvstore
			// connectivity which we can't do at this point. Let the lease
			// expire to release the identity.
			d.deleteEndpointQuiet(ep, endpoint.DeleteConfig{
				NoIdentityRelease: true,
				NoIPRelease:       true,
			})
			endpointCleanupCompleted.Done()
		}(ep)
	}
	endpointCleanupCompleted.Wait()

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
		close(restoreComplete)
	}()

	return
}

func (d *Daemon) allocateIPsLocked(ep *endpoint.Endpoint) error {
	var err error

	if option.Config.EnableIPv6 && ep.IPv6 != nil {
		err = d.ipam.AllocateIP(ep.IPv6.IP(), ep.HumanStringLocked()+" [restored]")
		if err != nil {
			return fmt.Errorf("unable to reallocate IPv6 address: %s", err)
		}

		defer func() {
			if err != nil {
				d.ipam.ReleaseIP(ep.IPv6.IP())
			}
		}()
	}

	if option.Config.EnableIPv4 && ep.IPv4 != nil {
		if err = d.ipam.AllocateIP(ep.IPv4.IP(), ep.HumanStringLocked()+" [restored]"); err != nil {
			return fmt.Errorf("unable to reallocate IPv4 address: %s", err)
		}
	}

	return nil
}

func (d *Daemon) initRestore(restoredEndpoints *endpointRestoreState) chan struct{} {
	bootstrapStats.restore.Start()
	var restoreComplete chan struct{}
	if option.Config.RestoreState {
		// When we regenerate restored endpoints, it is guaranteed tha we have
		// received the full list of policies present at the time the daemon
		// is bootstrapped.
		restoreComplete = d.regenerateRestoredEndpoints(restoredEndpoints)
		go func() {
			<-restoreComplete
			endParallelMapMode()
		}()

		go func() {
			if k8s.IsEnabled() {
				// Start controller which removes any leftover Kubernetes
				// services that may have been deleted while Cilium was not
				// running. Once this controller succeeds, because it has no
				// RunInterval specified, it will not run again unless updated
				// elsewhere. This means that if, for instance, a user manually
				// adds a service via the CLI into the BPF maps, that it will
				// not be cleaned up by the daemon until it restarts.
				controller.NewManager().UpdateController("sync-lb-maps-with-k8s-services",
					controller.ControllerParams{
						DoFunc: func(ctx context.Context) error {
							return d.syncLBMapsWithK8s()
						},
					},
				)
				return
			}
			if err := d.SyncLBMap(); err != nil {
				log.WithError(err).Warn("Error while recovering endpoints")
			}
		}()
	} else {
		log.Info("State restore is disabled. Existing endpoints on node are ignored")
		// We need to read all docker containers so we know we won't
		// going to allocate the same IP addresses and we will ignore
		// these containers from reading.
		workloads.IgnoreRunningWorkloads()

		// No restore happened, end parallel map mode immediately
		endParallelMapMode()
	}
	bootstrapStats.restore.End(true)

	return restoreComplete
}
