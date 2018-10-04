// Copyright 2018 Authors of Cilium
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

package cidr

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/cidr"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "identity-cidr")
)

// AllocateCIDRIdentities allocates identities for each of the specified CIDR
// prefixes so they will be available later during policy resolution.
//
// On success, the returned slice will have a 1-to-1 correspondence with the
// CIDR in the provided prefixes slice, eg the identity for prefixes[0] will
// be held in identities[0].
// On failure, attempts to clean up after itself and returns the error.
func AllocateCIDRIdentities(prefixes []*net.IPNet) (res []*identity.Identity, err error) {
	if len(prefixes) == 0 {
		return nil, nil
	}

	log.Debugf("Attempting to allocate identities for %d prefixes", len(prefixes))

	// Allocate identities for each CIDR.
	var lbls labels.Labels
	res = make([]*identity.Identity, len(prefixes))
	for i, prefix := range prefixes {
		if prefix == nil {
			continue
		}
		lbls := cidr.GetCIDRLabels(prefix)
		id, _, err := identity.AllocateIdentity(lbls)
		if err != nil {
			// If any identity allocation failed, release existing identities
			// and log the error.
			if err2 := identity.ReleaseSlice(res); err2 != nil {
				log.WithError(err2).Error("Could not recover from error during CIDR identity allocation")
			}
			res = nil
			break
		}
		res[i] = id
	}

	if err == nil {
		log.Debugf("Allocated identities for %d prefixes", len(res))
	} else {
		log.WithError(err).Warningf("Failed to allocate identities for %d prefixes", len(res))
	}

	if err != nil {
		err = fmt.Errorf("Failed to allocate identity for %s: %s", lbls.String(), err)
	}
	return
}

// LookupCIDRIdentities finds identities corresponding to each of the specified
// prefixes. It expects to be able to find all identities.
// On success, returns a slice of identities with a 1-to-1 correspondence to
// the specified slice of prefixes, and nil.
// On error, returns all identities that can be resolved and an error.
func LookupCIDRIdentities(prefixes []*net.IPNet) (res []*identity.Identity, err error) {
	res = make([]*identity.Identity, len(prefixes))

	for i, prefix := range prefixes {
		labels := cidr.GetCIDRLabels(prefix)
		if id := identity.LookupIdentity(labels); id != nil {
			res[i] = id
		} else {
			err = fmt.Errorf("Unable to find CIDR identity for labels %s", labels)
			log.Infof("Cannot locate identity for CIDR %s", prefix.String())
		}
	}

	return res, err
}
