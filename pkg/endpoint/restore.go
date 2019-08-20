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
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
)

// ReadEPsFromDirNames returns a mapping of endpoint ID to endpoint of endpoints
// from a list of directory names that can possible contain an endpoint.
func ReadEPsFromDirNames(owner regeneration.Owner, basePath string, eptsDirNames []string) map[uint16]*Endpoint {
	possibleEPs := map[uint16]*Endpoint{}
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
			scopedLog.Warning("C header file not found. Ignoring endpoint")
			continue
		}

		scopedLog.Debug("Found endpoint C header file")

		strEp, err := common.GetCiliumVersionString(cHeaderFile)
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to read the C header file")
			continue
		}
		ep, err := ParseEndpoint(owner, strEp)
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

	// NOTE: UnconditionalRLock is used here because it's used only for logging an already restored endpoint
	e.UnconditionalRLock()
	scopedLog.WithField(logfields.IPAddr, []string{e.IPv4.String(), e.IPv6.String()}).Info("Restored endpoint")
	e.RUnlock()
	return nil
}

func (e *Endpoint) restoreIdentity() error {
	if err := e.RLockAlive(); err != nil {
		e.LogDisconnectedMutexAction(err, "before filtering labels during regenerating restored endpoint")
		return err
	}
	scopedLog := log.WithField(logfields.EndpointID, e.ID)
	// Filter the restored labels with the new daemon's filter
	l, _ := labels.FilterLabels(e.OpLabels.AllLabels())
	e.RUnlock()

	allocateCtx, cancel := context.WithTimeout(context.Background(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()
	identity, _, err := cache.AllocateIdentity(allocateCtx, e.owner, l)

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

		err = cache.WaitForInitialGlobalIdentities(identityCtx)
		if err != nil {
			scopedLog.WithError(err).Warn("Failed while waiting for initial global identities")
			return err
		}
		if option.Config.KVStore != "" {
			ipcache.WaitForKVStoreSync()
		}
	}

	if err := e.LockAlive(); err != nil {
		scopedLog.Warn("Endpoint to restore has been deleted")
		return err
	}

	e.SetStateLocked(StateRestoring, "Synchronizing endpoint labels with KVStore")

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
			time.Sleep(defaults.IdentityChangeGracePeriod)
		}
	}
	// The identity of a freshly restored endpoint is incomplete due to some
	// parts of the identity not being marshaled to JSON. Hence we must set
	// the identity even if has not changed.
	e.SetIdentity(identity, true)
	e.Unlock()

	return nil
}
