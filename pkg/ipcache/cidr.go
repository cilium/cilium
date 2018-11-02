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

package ipcache

import (
	"net"

	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/cidr"

	"github.com/sirupsen/logrus"
)

// AllocateCIDRs attempts to allocate identities and IP<->Identity mappings for
// the specified CIDR prefixes. If any allocation fails, all allocations are
// rolled back and the error is returned. Returns nil on success.
func AllocateCIDRs(impl Implementation, prefixes []*net.IPNet) error {
	// First, if the implementation will complain, exit early.
	if err := checkPrefixes(impl, prefixes); err != nil {
		return err
	}

	// Next, allocate labels -> ID mappings in KVstore (for policy)
	prefixIdentities, err := cidr.AllocateCIDRIdentities(prefixes)
	if err != nil {
		return err
	}

	// Finally, allocate CIDR -> ID mappings in KVstore (for ipcache)
	err = upsertIPNetsToKVStore(prefixes, prefixIdentities)
	if err != nil {
		if err2 := cache.ReleaseSlice(prefixIdentities); err2 != nil {
			log.WithError(err2).WithFields(logrus.Fields{
				fieldIdentities: prefixIdentities,
			}).Warn("Failed to release CIDRs during CIDR->ID mapping")
		}
	}

	return err
}

// ReleaseCIDRs attempts to release identities and IP<->Identity mappings for
// the specified CIDR prefixes. If any release fails, all remaining prefixes
// will be attempted to be rolled back and an error is returned representing
// the most recent error. Returns nil if no errors occur.
func ReleaseCIDRs(prefixes []*net.IPNet) (err error) {
	scopedLog := log.WithField("prefixes", prefixes)
	if prefixes != nil {
		if err = deleteIPNetsFromKVStore(prefixes); err != nil {
			scopedLog.WithError(err).Debug(
				"Failed to release CIDR->Identity mappings")
		}
	}

	prefixIdentities, err2 := cidr.LookupCIDRIdentities(prefixes)
	if err2 != nil {
		if err == nil {
			err = err2
		}
		scopedLog.WithError(err2).Warning("Could not find identities for CIDRs during release")
	}
	if prefixIdentities != nil {
		if err2 = cache.ReleaseSlice(prefixIdentities); err2 != nil {
			if err == nil {
				err = err2
			}
			log.WithError(err2).WithFields(logrus.Fields{
				fieldIdentities: prefixIdentities,
			}).Warning("Failed to release Identities for CIDRs")
		}
	}

	return err
}
