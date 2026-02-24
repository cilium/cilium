// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	enitypes "github.com/cilium/cilium/pkg/aws/eni/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
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
	return in.Clientset.CiliumV2().CiliumNodes().Get(
		context.TODO(),
		nodetypes.GetName(),
		metav1.GetOptions{},
	)
}

// InterfaceDB contains all the ENIs on a given node. It is used to convert ENI
// MAC addrs from interface numbers and vice versa, needed for the ENI
// migration. See https://github.com/cilium/cilium/issues/14336.
type InterfaceDB struct {
	cache     enitypes.ENIStatus
	Clientset client.Clientset
}
