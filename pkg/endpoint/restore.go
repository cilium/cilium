// Copyright 2018-2019 Authors of Cilium
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

package endpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
)

// ReadEPsFromDirNames returns a mapping of endpoint ID to endpoint of endpoints
// from a list of directory names that can possible contain an endpoint.
func ReadEPsFromDirNames(ctx context.Context, owner regeneration.Owner, basePath string, eptsDirNames []string) map[uint16]*Endpoint {
	completeEPDirNames, incompleteEPDirNames := partitionEPDirNamesByRestoreStatus(eptsDirNames)

	if len(incompleteEPDirNames) > 0 {
		for _, epDirName := range incompleteEPDirNames {
			scopedLog := log.WithFields(logrus.Fields{
				logfields.EndpointID: epDirName,
			})
			fullDirName := filepath.Join(basePath, epDirName)
			scopedLog.Warning(fmt.Sprintf("Found incomplete restore directory %s. Removing it...", fullDirName))
			if err := os.RemoveAll(epDirName); err != nil {
				scopedLog.WithError(err).Warn(fmt.Sprintf("Error while removing directory %s. Ignoring it...", fullDirName))
			}
		}
	}

	possibleEPs := map[uint16]*Endpoint{}
	for _, epDirName := range completeEPDirNames {
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
			scopedLog.Warning("C header file not found. Ignoring endpoint")
			continue
		}

		scopedLog.Debug("Found endpoint C header file")

		strEp, err := common.GetCiliumVersionString(cHeaderFile)
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to read the C header file")
			continue
		}
		ep, err := parseEndpoint(ctx, owner, strEp)
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

// partitionEPDirNamesByRestoreStatus partitions the provided list of directory
// names that can possibly contain an endpoint, into two lists, containing those
// names that represent an incomplete endpoint restore and those that do not.
func partitionEPDirNamesByRestoreStatus(eptsDirNames []string) (complete []string, incomplete []string) {
	dirNames := make(map[string]struct{})
	for _, epDirName := range eptsDirNames {
		dirNames[epDirName] = struct{}{}
	}

	incompleteSuffixes := []string{nextDirectorySuffix, nextFailedDirectorySuffix}
	incompleteSet := make(map[string]struct{})

	for _, epDirName := range eptsDirNames {
		for _, suff := range incompleteSuffixes {
			if strings.HasSuffix(epDirName, suff) {
				if _, exists := dirNames[epDirName[:len(epDirName)-len(suff)]]; exists {
					incompleteSet[epDirName] = struct{}{}
				}
			}
		}
	}

	for epDirName := range dirNames {
		if _, exists := incompleteSet[epDirName]; exists {
			incomplete = append(incomplete, epDirName)
		} else {
			complete = append(complete, epDirName)
		}
	}

	return
}

// RegenerateAfterRestore performs the following operations on the specified
// Endpoint:
// * allocates an identity for the Endpoint
// * regenerates the endpoint
// Returns an error if any operation fails while trying to perform the above
// operations.
func (e *Endpoint) RegenerateAfterRestore() error {
	if err := e.restoreIdentity(); err != nil {
		return err
	}

	scopedLog := log.WithField(logfields.EndpointID, e.ID)

	regenerationMetadata := &regeneration.ExternalRegenerationMetadata{
		Reason: "syncing state to host",
	}
	if buildSuccess := <-e.Regenerate(regenerationMetadata); !buildSuccess {
		scopedLog.Warn("Failed while regenerating endpoint")
		return fmt.Errorf("failed while regenerating endpoint")
	}

	// NOTE: unconditionalRLock is used here because it's used only for logging an already restored endpoint
	e.unconditionalRLock()
	scopedLog.WithField(logfields.IPAddr, []string{e.IPv4.String(), e.IPv6.String()}).Info("Restored endpoint")
	e.runlock()
	return nil
}

func (e *Endpoint) restoreIdentity() error {
	if err := e.rlockAlive(); err != nil {
		e.logDisconnectedMutexAction(err, "before filtering labels during regenerating restored endpoint")
		return err
	}
	scopedLog := log.WithField(logfields.EndpointID, e.ID)
	// Filter the restored labels with the new daemon's filter
	l, _ := labels.FilterLabels(e.OpLabels.AllLabels())
	e.runlock()

	allocateCtx, cancel := context.WithTimeout(context.Background(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()
	identity, _, err := e.allocator.AllocateIdentity(allocateCtx, l, true)

	if err != nil {
		scopedLog.WithError(err).Warn("Unable to restore endpoint")
		return err
	}

	// Wait for initial identities and ipcache from the
	// kvstore before doing any policy calculation for
	// endpoints that don't have a fixed identity or are
	// not well known.
	if !identity.IsFixed() && !identity.IsWellKnown() {
		identityCtx, cancel := context.WithTimeout(context.Background(), option.Config.KVstoreConnectivityTimeout)
		defer cancel()

		err = e.allocator.WaitForInitialGlobalIdentities(identityCtx)
		if err != nil {
			scopedLog.WithError(err).Warn("Failed while waiting for initial global identities")
			return err
		}
		if option.Config.KVStore != "" {
			ipcache.WaitForKVStoreSync()
		}
	}

	if err := e.lockAlive(); err != nil {
		scopedLog.Warn("Endpoint to restore has been deleted")
		return err
	}

	e.setState(StateRestoring, "Synchronizing endpoint labels with KVStore")

	if e.SecurityIdentity != nil {
		if oldSecID := e.SecurityIdentity.ID; identity.ID != oldSecID {
			log.WithFields(logrus.Fields{
				logfields.EndpointID:              e.ID,
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
			time.Sleep(option.Config.IdentityChangeGracePeriod)
		}
	}
	// The identity of a freshly restored endpoint is incomplete due to some
	// parts of the identity not being marshaled to JSON. Hence we must set
	// the identity even if has not changed.
	e.SetIdentity(identity, true)
	e.unlock()

	return nil
}

// toSerializedEndpoint converts the Endpoint to its corresponding
// serializableEndpoint, which contains all of the fields that are needed upon
// restoring an Endpoint after cilium-agent restarts.
func (e *Endpoint) toSerializedEndpoint() *serializableEndpoint {

	return &serializableEndpoint{
		ID:                    e.ID,
		ContainerName:         e.containerName,
		ContainerID:           e.containerID,
		DockerNetworkID:       e.dockerNetworkID,
		DockerEndpointID:      e.dockerEndpointID,
		DatapathMapID:         e.datapathMapID,
		IfName:                e.ifName,
		IfIndex:               e.ifIndex,
		OpLabels:              e.OpLabels,
		LXCMAC:                e.mac,
		IPv6:                  e.IPv6,
		IPv4:                  e.IPv4,
		NodeMAC:               e.nodeMAC,
		SecurityIdentity:      e.SecurityIdentity,
		Options:               e.Options,
		DNSHistory:            e.DNSHistory,
		DNSZombies:            e.DNSZombies,
		K8sPodName:            e.K8sPodName,
		K8sNamespace:          e.K8sNamespace,
		DatapathConfiguration: e.DatapathConfiguration,
	}
}

// serializableEndpoint contains the fields from an Endpoint which are needed to be
// restored if cilium-agent restarts.
//
//
// WARNING - STABLE API
// This structure is written as JSON to StateDir/{ID}/lxc_config.h to allow to
// restore endpoints when the agent is being restarted. The restore operation
// will read the file and re-create all endpoints with all fields which are not
// marked as private to JSON marshal. Do NOT modify this structure in ways which
// is not JSON forward compatible.
//
type serializableEndpoint struct {
	// ID of the endpoint, unique in the scope of the node
	ID uint16

	// containerName is the name given to the endpoint by the container runtime
	ContainerName string

	// containerID is the container ID that docker has assigned to the endpoint
	// Note: The JSON tag was kept for backward compatibility.
	ContainerID string `json:"dockerID,omitempty"`

	// dockerNetworkID is the network ID of the libnetwork network if the
	// endpoint is a docker managed container which uses libnetwork
	DockerNetworkID string

	// dockerEndpointID is the Docker network endpoint ID if managed by
	// libnetwork
	DockerEndpointID string

	// Corresponding BPF map identifier for tail call map of ipvlan datapath
	DatapathMapID int

	// ifName is the name of the host facing interface (veth pair) which
	// connects into the endpoint
	IfName string

	// ifIndex is the interface index of the host face interface (veth pair)
	IfIndex int

	// OpLabels is the endpoint's label configuration
	//
	// FIXME: Rename this field to Labels
	OpLabels labels.OpLabels

	// mac is the MAC address of the endpoint
	//
	// FIXME: Rename this field to MAC
	LXCMAC mac.MAC // Container MAC address.

	// IPv6 is the IPv6 address of the endpoint
	IPv6 addressing.CiliumIPv6

	// IPv4 is the IPv4 address of the endpoint
	IPv4 addressing.CiliumIPv4

	// nodeMAC is the MAC of the node (agent). The MAC is different for every endpoint.
	NodeMAC mac.MAC

	// SecurityIdentity is the security identity of this endpoint. This is computed from
	// the endpoint's labels.
	SecurityIdentity *identity.Identity `json:"SecLabel"`

	// Options determine the datapath configuration of the endpoint.
	Options *option.IntOptions

	// DNSHistory is the collection of still-valid DNS responses intercepted for
	// this endpoint.
	DNSHistory *fqdn.DNSCache

	// DNSZombies is the collection of DNS entries that have been expired or
	// evicted from DNSHistory.
	DNSZombies *fqdn.DNSZombieMappings

	// K8sPodName is the Kubernetes pod name of the endpoint
	K8sPodName string

	// K8sNamespace is the Kubernetes namespace of the endpoint
	K8sNamespace string

	// DatapathConfiguration is the endpoint's datapath configuration as
	// passed in via the plugin that created the endpoint, e.g. the CNI
	// plugin which performed the plumbing will enable certain datapath
	// features according to the mode selected.
	DatapathConfiguration models.EndpointDatapathConfiguration
}

// UnmarshalJSON expects that the contents of `raw` are a serializableEndpoint,
// which is then converted into an Endpoint.
func (ep *Endpoint) UnmarshalJSON(raw []byte) error {
	// We may have to populate structures in the Endpoint manually to do the
	// translation from serializableEndpoint --> Endpoint.
	restoredEp := &serializableEndpoint{
		OpLabels:   labels.NewOpLabels(),
		DNSHistory: fqdn.NewDNSCacheWithLimit(option.Config.ToFQDNsMinTTL, option.Config.ToFQDNsMaxIPsPerHost),
		DNSZombies: fqdn.NewDNSZombieMappings(option.Config.ToFQDNsMaxDeferredConnectionDeletes),
	}
	if err := json.Unmarshal(raw, restoredEp); err != nil {
		return fmt.Errorf("error unmarshaling serializableEndpoint from base64 representation: %s", err)
	}

	ep.fromSerializedEndpoint(restoredEp)
	return nil
}

// MarshalJSON marshals the Endpoint as its serializableEndpoint representation.
func (ep *Endpoint) MarshalJSON() ([]byte, error) {
	return json.Marshal(ep.toSerializedEndpoint())
}

func (ep *Endpoint) fromSerializedEndpoint(r *serializableEndpoint) {
	ep.ID = r.ID
	ep.containerName = r.ContainerName
	ep.containerID = r.ContainerID
	ep.dockerNetworkID = r.DockerNetworkID
	ep.dockerEndpointID = r.DockerEndpointID
	ep.datapathMapID = r.DatapathMapID
	ep.ifName = r.IfName
	ep.ifIndex = r.IfIndex
	ep.OpLabels = r.OpLabels
	ep.mac = r.LXCMAC
	ep.IPv6 = r.IPv6
	ep.IPv4 = r.IPv4
	ep.nodeMAC = r.NodeMAC
	ep.SecurityIdentity = r.SecurityIdentity
	ep.DNSHistory = r.DNSHistory
	ep.DNSZombies = r.DNSZombies
	ep.K8sPodName = r.K8sPodName
	ep.K8sNamespace = r.K8sNamespace
	ep.DatapathConfiguration = r.DatapathConfiguration
	ep.Options = r.Options
}
