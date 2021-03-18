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

// This package contains the WireGuard operator code, which is responsible to
// allocate and set the WireGuard tunnel device IP address in the CiliumNode
// object.
package operator

import (
	"errors"
	"fmt"
	"net"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/wireguard/types"

	"github.com/cilium/ipam/service/ipallocator"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/retry"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "wireguard")

type CiliumNodeUpdater interface {
	Update(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error)
	Get(node string) (*v2.CiliumNode, error)
}

// Operator is initialized with NewOperator()
//
// The operator starts in restoring mode, when it will not attempt to allocate
// any IPs and, instead, place nodes in ipv{4,6}AllocAfterRestore so that their
// IPs can be allocated on RestoreFinished()
type Operator struct {
	lock.RWMutex
	restoring             bool
	ciliumNodeUpdater     CiliumNodeUpdater
	ipv4Alloc             *ipallocator.Range
	ipv4ByNode            map[string]net.IP
	ipv4AllocAfterRestore map[string]struct{} // by nodename
	ipv6Alloc             *ipallocator.Range
	ipv6ByNode            map[string]net.IP
	ipv6AllocAfterRestore map[string]struct{} // by nodename
}

// NewOperator creates an instance of the Wireguard operator.
func NewOperator(subnetV4, subnetV6 *net.IPNet, ciliumNodeUpdater CiliumNodeUpdater) (*Operator, error) {
	var (
		err                                          error
		ipv4Alloc, ipv6Alloc                         *ipallocator.Range
		ipv4ByNode, ipv6ByNode                       map[string]net.IP
		ipv4AllocAfterRestore, ipv6AllocAfterRestore map[string]struct{}
	)

	if option.Config.EnableIPv4 {
		ipv4ByNode = make(map[string]net.IP)
		ipv4AllocAfterRestore = make(map[string]struct{})
		ipv4Alloc, err = ipallocator.NewCIDRRange(subnetV4)
		if err != nil {
			return nil, err
		}
	}

	if option.Config.EnableIPv6 {
		ipv6ByNode = make(map[string]net.IP)
		ipv6AllocAfterRestore = make(map[string]struct{})
		ipv6Alloc, err = ipallocator.NewCIDRRange(subnetV6)
		if err != nil {
			return nil, err
		}
	}

	return &Operator{
		restoring:             true,
		ciliumNodeUpdater:     ciliumNodeUpdater,
		ipv4Alloc:             ipv4Alloc,
		ipv4ByNode:            ipv4ByNode,
		ipv4AllocAfterRestore: ipv4AllocAfterRestore,
		ipv6Alloc:             ipv6Alloc,
		ipv6ByNode:            ipv6ByNode,
		ipv6AllocAfterRestore: ipv6AllocAfterRestore,
	}, nil
}

// AddNode is called by cilium-operator when a new CiliumNode is created.
func (o *Operator) AddNode(n *v2.CiliumNode) error {
	o.Lock()
	defer o.Unlock()

	if option.Config.EnableIPv4 {
		if err := o.allocateIP(n, types.IPv4); err != nil {
			return err
		}
	}

	if option.Config.EnableIPv6 {
		if err := o.allocateIP(n, types.IPv6); err != nil {
			return err
		}
	}

	return nil
}

// UpdateNode is called by cilium-operator when an existing CiliumNode is updated.
func (o *Operator) UpdateNode(n *v2.CiliumNode) error {
	o.Lock()
	defer o.Unlock()

	if option.Config.EnableIPv4 {
		if err := o.allocateIP(n, types.IPv4); err != nil {
			return err
		}
	}

	if option.Config.EnableIPv6 {
		if err := o.allocateIP(n, types.IPv6); err != nil {
			return err
		}
	}

	return nil
}

// DeleteNode is called by cilium-operator when an existing CiliumNode is removed.
func (o *Operator) DeleteNode(n *v2.CiliumNode) {
	o.Lock()
	defer o.Unlock()

	nodeName := n.ObjectMeta.Name

	if o.restoring {
		log.WithField(logfields.NodeName, nodeName).Warn("Received node delete while restoring")
	}

	if option.Config.EnableIPv4 {
		o.releaseIP(n, nodeName, types.IPv4)
	}

	if option.Config.EnableIPv6 {
		o.releaseIP(n, nodeName, types.IPv6)
	}
}

func (o *Operator) releaseIP(n *v2.CiliumNode, nodeName string, family types.Family) {
	var (
		ipAlloc  *ipallocator.Range
		ipByNode map[string]net.IP
	)

	switch family {
	case types.IPv4:
		ipAlloc = o.ipv4Alloc
		ipByNode = o.ipv4ByNode
	case types.IPv6:
		ipAlloc = o.ipv6Alloc
		ipByNode = o.ipv6ByNode
	default:
		panic(fmt.Sprintf("unsupported family: %s", family))
	}

	ip, found := findWireguardIP(n, family)

	if !found {
		// Maybe cilium-agent has removed the IP addr from CiliumNode, so fallback
		// to local cache to determine the IP addr.
		ip, found = ipByNode[nodeName]
	}

	if found {
		ipAlloc.Release(ip)
		delete(ipByNode, nodeName)

		log.WithFields(logrus.Fields{
			logfields.NodeName: nodeName,
			logfields.IPAddr:   ip,
		}).Info("Released wireguard IP")
	}
}

// RestoreFinished is called by cilium-operator once it has received all
// CiliumNodes from kube-apiserver during its restore.
//
// RestoreFinished removes IP allocations of CiliumNodes which no longer exist.
func (o *Operator) RestoreFinished() error {
	o.Lock()
	defer o.Unlock()

	for nodeName := range o.ipv4AllocAfterRestore {
		ip, err := o.ipv4Alloc.AllocateNext()
		if err != nil {
			return fmt.Errorf("failed to allocate IPv4 addr for node %s: %w", nodeName, err)
		}
		if err := o.setCiliumNodeIP(nodeName, ip); err != nil {
			o.ipv4Alloc.Release(ip)
			return err
		}
		o.ipv4ByNode[nodeName] = ip
	}

	for nodeName := range o.ipv6AllocAfterRestore {
		ip, err := o.ipv6Alloc.AllocateNext()
		if err != nil {
			return fmt.Errorf("failed to allocate IPv6 addr for node %s: %w", nodeName, err)
		}
		if err := o.setCiliumNodeIP(nodeName, ip); err != nil {
			o.ipv6Alloc.Release(ip)
			return err
		}
		o.ipv6ByNode[nodeName] = ip
	}

	o.restoring = false
	o.ipv4AllocAfterRestore = nil
	o.ipv6AllocAfterRestore = nil

	return nil
}

func findWireguardIP(n *v2.CiliumNode, family types.Family) (net.IP, bool) {
	var ip net.IP
	for _, addr := range n.Spec.Addresses {
		if addr.Type == addressing.NodeWireguardIP {
			ip = net.ParseIP(addr.IP)
			if ip != nil {
				isIPv4 := ip.To4() != nil
				if (family == types.IPv4 && isIPv4) || (family == types.IPv6 && !isIPv4) {
					return ip, true
				}
			}
		}
	}

	return nil, false
}

// allocateIP must be called with *Operator mutex being held.
func (o *Operator) allocateIP(n *v2.CiliumNode, family types.Family) error {
	var (
		ipAlloc             *ipallocator.Range
		ipByNode            map[string]net.IP
		ipAllocAfterRestore map[string]struct{}
	)
	switch family {
	case types.IPv4:
		ipAlloc = o.ipv4Alloc
		ipByNode = o.ipv4ByNode
		ipAllocAfterRestore = o.ipv4AllocAfterRestore
	case types.IPv6:
		ipAlloc = o.ipv6Alloc
		ipByNode = o.ipv6ByNode
		ipAllocAfterRestore = o.ipv6AllocAfterRestore
	default:
		return errors.New("unsupported family")
	}

	nodeName := n.ObjectMeta.Name
	allocated := false
	defer func() {
		if allocated {
			log.WithFields(logrus.Fields{
				logfields.NodeName: nodeName,
				logfields.IPAddr:   ipByNode[nodeName],
			}).Info("Allocated wireguard IP")
		}
	}()

	ip, found := findWireguardIP(n, family)

	if o.restoring && !found {
		// We will allocate an IP once we have learned about all previously
		// allocated IPs (after sync with k8s has finished).
		ipAllocAfterRestore[nodeName] = struct{}{}
		return nil
	}

	if !found {
		// No IP was found in CiliumNode, so let's allocate one

		var ip net.IP
		var err error
		if prevIP, ok := ipByNode[nodeName]; ok {
			ip = prevIP
			// Previously, the node had an IP assigned to it, so let's reallocate
			// it. This can happen when someone manually removes the wireguard IP
			// from CiliumNode object.
			err = ipAlloc.Allocate(prevIP)
			if err != nil && !errors.Is(err, ipallocator.ErrAllocated) {
				return fmt.Errorf("failed to re-allocate IP addr for node %s: %w", nodeName, err)
			}
		} else {
			ip, err = ipAlloc.AllocateNext()
			if err != nil {
				return fmt.Errorf("failed to allocate IP addr for node %s: %w", nodeName, err)
			}
		}

		if err := o.setCiliumNodeIP(nodeName, ip); err != nil {
			ipAlloc.Release(ip)
			return err
		}
		ipByNode[nodeName] = ip
		allocated = true

		return nil
	}

	// An IP was found in CiliumNode. This could happen in both states
	// (restoring and after restoring).
	if prevIP, ok := ipByNode[nodeName]; ok {
		if !prevIP.Equal(ip) {
			// The IP we previously learnt does not match. Release it first before
			// we reallocate the IP from CiliumNode
			ipAlloc.Release(prevIP)
			delete(ipByNode, nodeName)

			if err := ipAlloc.Allocate(ip); err != nil {
				return fmt.Errorf("failed to re-allocate IP addr %s for node %s: %w", ip, nodeName, err)
			}
			ipByNode[nodeName] = ip
		}
	} else {
		// We don't know about this IP, let's allocate it (can happen during
		// restore).
		if err := ipAlloc.Allocate(ip); err != nil {
			return err
		}
		ipByNode[nodeName] = ip
	}

	return nil
}

func (o *Operator) setCiliumNodeIP(nodeName string, ip net.IP) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := o.ciliumNodeUpdater.Get(nodeName)
		if err != nil {
			return err
		}

		for _, addr := range node.Spec.Addresses {
			if addr.Type == addressing.NodeWireguardIP {
				if foundIP := net.ParseIP(addr.IP); foundIP != nil && foundIP.Equal(ip) {
					return nil
				}
			}
		}

		node.Spec.Addresses = append(node.Spec.Addresses, v2.NodeAddress{Type: addressing.NodeWireguardIP, IP: ip.String()})
		_, err = o.ciliumNodeUpdater.Update(nil, node)
		return err
	})

	scopedLog := log.WithFields(logrus.Fields{
		logfields.NodeName: nodeName,
		logfields.IPAddr:   ip,
	})

	if err != nil {
		scopedLog.Info("Set wireguard IP")
	} else {
		scopedLog.WithError(err).Warn("Set wireguard IP failed")
	}

	return err
}
