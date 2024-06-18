// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func populateBackendMapV3FromV2(ipv4, ipv6 bool) error {
	const (
		v4 = "ipv4"
		v6 = "ipv6"
	)

	enabled := map[string]bool{v4: ipv4, v6: ipv6}

	for v, e := range enabled {
		if !e {
			continue
		}

		var (
			err          error
			v2Map        *bpf.Map
			v3Map        *bpf.Map
			v3BackendVal BackendValue
		)

		copyBackendEntries := func(key bpf.MapKey, value bpf.MapValue) {
			if v == v4 {
				v3Map = Backend4MapV3
				v1BackendVal := value.(*Backend4Value)
				addrCluster := cmtypes.AddrClusterFrom(v1BackendVal.Address.Addr(), 0)
				v3BackendVal, err = NewBackend4ValueV3(
					addrCluster,
					v1BackendVal.Port,
					v1BackendVal.Proto,
					loadbalancer.GetBackendStateFromFlags(v1BackendVal.Flags),
					0,
				)
				if err != nil {
					log.WithError(err).WithField(logfields.BPFMapName, v3Map.Name()).Debug("Error creating map value")
					return
				}
			} else {
				v3Map = Backend6MapV3
				v1BackendVal := value.(*Backend6Value)
				addrCluster := cmtypes.AddrClusterFrom(v1BackendVal.Address.Addr(), 0)
				v3BackendVal, err = NewBackend6ValueV3(
					addrCluster,
					v1BackendVal.Port,
					v1BackendVal.Proto,
					loadbalancer.GetBackendStateFromFlags(v1BackendVal.Flags),
					0,
				)
				if err != nil {
					log.WithError(err).WithField(logfields.BPFMapName, v3Map.Name()).Debug("Error creating map value")
					return
				}
			}

			err := v3Map.Update(key, v3BackendVal)
			if err != nil {
				log.WithError(err).WithField(logfields.BPFMapName, v3Map.Name()).Warn("Error updating map")
			}
		}

		if v == v4 {
			v2Map = Backend4MapV2
		} else {
			v2Map = Backend6MapV2
		}

		err = v2Map.DumpWithCallback(copyBackendEntries)
		if err != nil {
			return fmt.Errorf("unable to populate %s: %w", v2Map.Name(), err)
		}

		// V2 backend map will be removed from bpffs at this point,
		// the map will be actually removed once the last program
		// referencing it has been removed.
		err = v2Map.Close()
		if err != nil {
			log.WithError(err).WithField(logfields.BPFMapName, v2Map.Name()).Warn("Error closing map")
		}

		err = v2Map.Unpin()
		if err != nil {
			log.WithError(err).WithField(logfields.BPFMapName, v2Map.Name()).Warn("Error unpinning map")
		}

	}
	return nil
}
