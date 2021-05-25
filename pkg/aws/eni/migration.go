// Copyright 2021 Authors of Cilium
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

package eni

import (
	"context"
	"fmt"

	enitypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	nodetypes "github.com/cilium/cilium/pkg/node/types"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetInterfaceNumberByMAC implements the linuxrouting.interfaceDB interface.
// It retrieves the number associated with the ENI device for the given MAC
// address. The interface number is retrieved from the CiliumNode resource, as
// this functionality is needed for ENI mode.
func (in *InterfaceDB) GetInterfaceNumberByMAC(mac string) (int, error) {
	// Update the cache on the first run. After retrieving the CiliumNode
	// resource, we use the cached result for the remainder of the migration.
	if len(in.cache.ENIs) == 0 {
		cn, err := in.fetchFromK8s(nodetypes.GetName())
		if err != nil {
			return -1, err
		}

		in.cache = cn.Status.ENI
	}

	var (
		eni   enitypes.ENI
		found bool
	)
	for _, e := range in.cache.ENIs {
		if e.MAC == mac {
			eni = e
			found = true
			break
		}
	}

	if !found {
		return -1, fmt.Errorf("could not find interface with MAC %q in CiliumNode resource", mac)
	}

	return eni.Number, nil
}

// GetMACByInterfaceNumber retrieves the MAC address from a given ENI's
// interface number. This implements the linuxrouting.interfaceDB interface.
func (in *InterfaceDB) GetMACByInterfaceNumber(ifaceNum int) (string, error) {
	// Update the cache on the first run. After retrieving the CiliumNode
	// resource, we use the cached result for the remainder of the migration.
	if len(in.cache.ENIs) == 0 {
		cn, err := in.fetchFromK8s(nodetypes.GetName())
		if err != nil {
			return "", err
		}

		in.cache = cn.Status.ENI
	}

	var (
		eni   enitypes.ENI
		found bool
	)
	for _, e := range in.cache.ENIs {
		if e.Number == ifaceNum {
			eni = e
			found = true
			break
		}
	}

	if !found {
		return "", fmt.Errorf("could not find interface with number %q in CiliumNode resource", ifaceNum)
	}

	return eni.MAC, nil
}

func (in *InterfaceDB) fetchFromK8s(name string) (*v2.CiliumNode, error) {
	return k8s.CiliumClient().CiliumV2().CiliumNodes().Get(
		context.TODO(),
		nodetypes.GetName(),
		v1.GetOptions{},
	)
}

// InterfaceDB contains all the ENIs on a given node. It is used to convert ENI
// MAC addrs from interface numbers and vice versa, needed for the ENI
// migration. See https://github.com/cilium/cilium/issues/14336.
type InterfaceDB struct {
	cache enitypes.ENIStatus
}
