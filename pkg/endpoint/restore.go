// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// getCiliumVersionString returns the first line containing ciliumCHeaderPrefix.
func getCiliumVersionString(epCHeaderFilePath string) ([]byte, error) {
	f, err := os.Open(epCHeaderFilePath)
	if err != nil {
		return []byte{}, err
	}
	br := bufio.NewReader(f)
	defer f.Close()
	for {
		b, err := br.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			return []byte{}, nil
		}
		if err != nil {
			return []byte{}, err
		}
		if bytes.Contains(b, []byte(ciliumCHeaderPrefix)) {
			return b, nil
		}
	}
}

// hostObjFileName is the name of the host object file.
const hostObjFileName = "bpf_host.o"

func hasHostObjectFile(epDir string) bool {
	hostObjFilepath := filepath.Join(epDir, hostObjFileName)
	_, err := os.Stat(hostObjFilepath)
	return err == nil
}

// ReadEPsFromDirNames returns a mapping of endpoint ID to endpoint of endpoints
// from a list of directory names that can possible contain an endpoint.
func ReadEPsFromDirNames(ctx context.Context, owner regeneration.Owner, policyGetter policyRepoGetter,
	namedPortsGetter namedPortsGetter, basePath string, eptsDirNames []string) map[uint16]*Endpoint {

	completeEPDirNames, incompleteEPDirNames := partitionEPDirNamesByRestoreStatus(eptsDirNames)

	if len(incompleteEPDirNames) > 0 {
		for _, epDirName := range incompleteEPDirNames {
			scopedLog := log.WithFields(logrus.Fields{
				logfields.EndpointID: epDirName,
			})
			fullDirName := filepath.Join(basePath, epDirName)
			scopedLog.Info(fmt.Sprintf("Found incomplete restore directory %s. Removing it...", fullDirName))
			if err := os.RemoveAll(epDirName); err != nil {
				scopedLog.WithError(err).Warn(fmt.Sprintf("Error while removing directory %s. Ignoring it...", fullDirName))
			}
		}
	}

	possibleEPs := map[uint16]*Endpoint{}
	for _, epDirName := range completeEPDirNames {
		epDir := filepath.Join(basePath, epDirName)
		isHost := hasHostObjectFile(epDir)

		cHeaderFile := filepath.Join(epDir, common.CHeaderFileName)
		scopedLog := log.WithFields(logrus.Fields{
			logfields.EndpointID: epDirName,
			logfields.Path:       cHeaderFile,
		})
		// This function checks the presence of a bug previously observed: the
		// file was sometimes only found after the second check.
		// We can remove this if we haven't seen the issue occur after a while.
		headerFileExists := func() error {
			_, fileExists := os.Stat(cHeaderFile)
			for i := 0; i < 2 && fileExists != nil; i++ {
				time.Sleep(100 * time.Millisecond)
				_, err := os.Stat(cHeaderFile)
				if (fileExists == nil) != (err == nil) {
					scopedLog.WithError(err).Warn("BUG: stat() has unstable behavior")
				}
				fileExists = err
			}
			return fileExists
		}

		if err := headerFileExists(); err != nil {
			scopedLog.WithError(err).Warn("C header file not found. Ignoring endpoint")
			continue
		}

		scopedLog.Debug("Found endpoint C header file")

		bEp, err := getCiliumVersionString(cHeaderFile)
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to read the C header file")
			continue
		}
		ep, err := parseEndpoint(ctx, owner, policyGetter, namedPortsGetter, bEp)
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

		// We need to save the host endpoint ID as we'll need it to regenerate
		// other endpoints.
		if isHost {
			node.SetEndpointID(ep.GetID())
		}
	}
	return possibleEPs
}

// partitionEPDirNamesByRestoreStatus partitions the provided list of directory
// names that can possibly contain an endpoint, into two lists, containing those
// names that represent an incomplete endpoint restore and those that do not.
func partitionEPDirNamesByRestoreStatus(eptsDirNames []string) (complete []string, incomplete []string) {
	dirNames := make(map[string]struct{}, len(eptsDirNames))
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
		Reason:            "syncing state to host",
		RegenerationLevel: regeneration.RegenerateWithDatapathRewrite,
	}
	if buildSuccess := <-e.Regenerate(regenerationMetadata); !buildSuccess {
		return fmt.Errorf("failed while regenerating endpoint")
	}

	// NOTE: unconditionalRLock is used here because it's used only for logging an already restored endpoint
	e.unconditionalRLock()
	scopedLog.WithField(logfields.IPAddr, []string{e.GetIPv4Address(), e.GetIPv6Address()}).Info("Restored endpoint")
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
	l, _ := labelsfilter.Filter(e.OpLabels.AllLabels())
	e.runlock()

	// Getting the ep's identity while we are restoring should block the
	// restoring of the endpoint until we get its security identity ID.
	// If the endpoint is removed, this controller will cancel the allocator
	// requests.
	controllerName := fmt.Sprintf("restoring-ep-identity (%v)", e.ID)
	var (
		id                *identity.Identity
		allocatedIdentity = make(chan struct{})
	)
	e.UpdateController(controllerName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) (err error) {
				allocateCtx, cancel := context.WithTimeout(ctx, option.Config.KVstoreConnectivityTimeout)
				defer cancel()
				id, _, err = e.allocator.AllocateIdentity(allocateCtx, l, true, identity.InvalidIdentity)
				if err != nil {
					return err
				}
				close(allocatedIdentity)
				return nil
			},
		})

	// Wait until we either get an identity or the endpoint is removed or
	// deleted from the node.
	select {
	case <-e.aliveCtx.Done():
		return ErrNotAlive
	case <-allocatedIdentity:
	}

	// Wait for initial identities and ipcache from the
	// kvstore before doing any policy calculation for
	// endpoints that don't have a fixed identity or are
	// not well known.
	if !id.IsFixed() && !id.IsWellKnown() {
		// Getting the initial global identities while we are restoring should
		// block the restoring of the endpoint.
		// If the endpoint is removed, this controller will cancel the allocator
		// WaitForInitialGlobalIdentities function.
		controllerName := fmt.Sprintf("waiting-initial-global-identities-ep (%v)", e.ID)
		var gotInitialGlobalIdentities = make(chan struct{})
		e.UpdateController(controllerName,
			controller.ControllerParams{
				DoFunc: func(ctx context.Context) (err error) {
					identityCtx, cancel := context.WithTimeout(ctx, option.Config.KVstoreConnectivityTimeout)
					defer cancel()

					err = e.allocator.WaitForInitialGlobalIdentities(identityCtx)
					if err != nil {
						scopedLog.WithError(err).Warn("Failed while waiting for initial global identities")
						return err
					}
					close(gotInitialGlobalIdentities)
					return nil
				},
			})

		// Wait until we either the initial global identities or the endpoint
		// is deleted.
		select {
		case <-e.aliveCtx.Done():
			return ErrNotAlive
		case <-gotInitialGlobalIdentities:
		}
	}

	// Wait for ipcache sync before regeneration for endpoints including
	// the ones with fixed identity (e.g. host endpoint), this ensures that
	// the regenerated datapath always lookups from a ready ipcache map.
	if option.Config.KVStore != "" {
		ipcache.WaitForKVStoreSync()
	}

	if err := e.lockAlive(); err != nil {
		scopedLog.Warn("Endpoint to restore has been deleted")
		return err
	}

	e.setState(StateRestoring, "Synchronizing endpoint labels with KVStore")

	if e.SecurityIdentity != nil {
		if oldSecID := e.SecurityIdentity.ID; id.ID != oldSecID {
			log.WithFields(logrus.Fields{
				logfields.EndpointID:              e.ID,
				logfields.IdentityLabels + ".old": oldSecID,
				logfields.IdentityLabels + ".new": id.ID,
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
	e.SetIdentity(id, true)
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
		IfName:                e.ifName,
		IfIndex:               e.ifIndex,
		OpLabels:              e.OpLabels,
		LXCMAC:                e.mac,
		IPv6:                  e.IPv6,
		IPv6IPAMPool:          e.IPv6IPAMPool,
		IPv4:                  e.IPv4,
		IPv4IPAMPool:          e.IPv4IPAMPool,
		NodeMAC:               e.nodeMAC,
		SecurityIdentity:      e.SecurityIdentity,
		Options:               e.Options,
		DNSRules:              e.DNSRules,
		DNSHistory:            e.DNSHistory,
		DNSZombies:            e.DNSZombies,
		K8sPodName:            e.K8sPodName,
		K8sNamespace:          e.K8sNamespace,
		DatapathConfiguration: e.DatapathConfiguration,
		CiliumEndpointUID:     e.ciliumEndpointUID,
	}
}

// serializableEndpoint contains the fields from an Endpoint which are needed to be
// restored if cilium-agent restarts.
//
// WARNING - STABLE API
// This structure is written as JSON to StateDir/{ID}/ep_config.h to allow to
// restore endpoints when the agent is being restarted. The restore operation
// will read the file and re-create all endpoints with all fields which are not
// marked as private to JSON marshal. Do NOT modify this structure in ways which
// is not JSON forward compatible.
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
	IPv6 netip.Addr

	// IPv6IPAMPool is the IPAM address pool from which the IPv6 address was allocated
	IPv6IPAMPool string

	// IPv4 is the IPv4 address of the endpoint
	IPv4 netip.Addr

	// IPv4IPAMPool is the IPAM address pool from which the IPv4 address was allocated
	IPv4IPAMPool string

	// nodeMAC is the MAC of the node (agent). The MAC is different for every endpoint.
	NodeMAC mac.MAC

	// SecurityIdentity is the security identity of this endpoint. This is computed from
	// the endpoint's labels.
	SecurityIdentity *identity.Identity `json:"SecLabel"`

	// Options determine the datapath configuration of the endpoint.
	Options *option.IntOptions

	// DNSRules is the collection of current DNS rules for this endpoint.
	DNSRules restore.DNSRules

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

	// CiliumEndpointUID contains the unique identifier ref for the CiliumEndpoint
	// that this Endpoint was managing.
	// This is used to avoid overwriting/deleting ciliumendpoints that are managed
	// by other endpoints.
	CiliumEndpointUID types.UID
}

// UnmarshalJSON expects that the contents of `raw` are a serializableEndpoint,
// which is then converted into an Endpoint.
func (ep *Endpoint) UnmarshalJSON(raw []byte) error {
	// We may have to populate structures in the Endpoint manually to do the
	// translation from serializableEndpoint --> Endpoint.
	restoredEp := &serializableEndpoint{
		OpLabels:   labels.NewOpLabels(),
		DNSHistory: fqdn.NewDNSCacheWithLimit(option.Config.ToFQDNsMinTTL, option.Config.ToFQDNsMaxIPsPerHost),
		DNSZombies: fqdn.NewDNSZombieMappings(option.Config.ToFQDNsMaxDeferredConnectionDeletes, option.Config.ToFQDNsMaxIPsPerHost),
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
	ep.createdAt = time.Now()
	ep.containerName = r.ContainerName
	ep.containerID = r.ContainerID
	ep.dockerNetworkID = r.DockerNetworkID
	ep.dockerEndpointID = r.DockerEndpointID
	ep.ifName = r.IfName
	ep.ifIndex = r.IfIndex
	ep.OpLabels = r.OpLabels
	ep.mac = r.LXCMAC
	ep.IPv6 = r.IPv6
	ep.IPv6IPAMPool = r.IPv6IPAMPool
	ep.IPv4 = r.IPv4
	ep.IPv4IPAMPool = r.IPv4IPAMPool
	ep.nodeMAC = r.NodeMAC
	ep.SecurityIdentity = r.SecurityIdentity
	ep.DNSRules = r.DNSRules
	ep.DNSHistory = r.DNSHistory
	ep.DNSZombies = r.DNSZombies
	ep.K8sPodName = r.K8sPodName
	ep.K8sNamespace = r.K8sNamespace
	ep.DatapathConfiguration = r.DatapathConfiguration
	ep.Options = r.Options
	ep.ciliumEndpointUID = r.CiliumEndpointUID
}
