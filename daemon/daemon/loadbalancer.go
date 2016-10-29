//
// Copyright 2016 Authors of Cilium
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
//
package daemon

import (
	"fmt"

	"github.com/cilium/cilium/bpf/lbmap"
	"github.com/cilium/cilium/common/types"
)

// SVCAdd adds a service from the given fe (frontend) and bes (backends) with the given
// id. If addRevNAT is set, the RevNAT entry is also created for this particular service.
// If any of the backend addresses set in bes have a different L3 address type than the
// one set in fe, it returns an error without modifying the bpf LB map. If any backend
// entry fails while updating the LB map, the frontend won't be inserted in the LB map and
// therefore there won't be any traffic going to the given backends.
func (d *Daemon) SVCAdd(id types.ServiceID, fe lbmap.ServiceKey, bes []types.L3n4Addr, addRevNAT bool) error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	// Create a list of ServiceValues so we know everything is safe to put in the lb
	// map
	besValues := []lbmap.ServiceValue{}
	for _, be := range bes {
		beValue := fe.NewValue().(lbmap.ServiceValue)
		if err := beValue.SetAddress(be.IP); err != nil {
			return err
		}
		beValue.SetPort(uint16(be.Port))
		beValue.SetRevNat(int(id))

		besValues = append(besValues, beValue)
	}

	// Put all the backend services first
	nSvcs := 1
	for _, be := range besValues {
		fe.SetBackend(nSvcs)
		if err := lbmap.UpdateService(fe, be); err != nil {
			return fmt.Errorf("unable to update service %+v with the value %+v: %s", fe, be, err)
		}
		nSvcs++
	}

	var err error
	if addRevNAT {
		zeroValue := fe.NewValue().(lbmap.ServiceValue)
		zeroValue.SetRevNat(int(id))
		revNATKey := zeroValue.RevNatKey()
		revNATValue := fe.RevNatValue()
		if err := lbmap.UpdateRevNat(revNATKey, revNATValue); err != nil {
			return fmt.Errorf("unable to update reverse NAT %+v with value %+v, %s", revNATKey, revNATValue, err)
		}
		defer func() {
			if err != nil {
				lbmap.DeleteRevNat(revNATKey)
			}
		}()
	}

	fe.SetBackend(0)
	zeroValue := fe.NewValue().(lbmap.ServiceValue)
	zeroValue.SetCount(nSvcs - 1)

	err = lbmap.UpdateService(fe, zeroValue)
	if err != nil {
		return fmt.Errorf("unable to update service %+v with the value %+v: %s", fe, zeroValue, err)
	}

	return nil
}

// SVCDelete deletes the svcKey from the local bpf map.
func (d *Daemon) SVCDelete(svcKey lbmap.ServiceKey) error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()
	svcKey.SetBackend(0)
	return lbmap.DeleteService(svcKey)
}

// RevNATDelete deletes the revNatKey from the local bpf map.
func (d *Daemon) RevNATDelete(revNatKey lbmap.RevNatKey) error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()
	return lbmap.DeleteRevNat(revNatKey)
}
