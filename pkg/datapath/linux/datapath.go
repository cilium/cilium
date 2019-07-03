// Copyright 2019 Authors of Cilium
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

package linux

import (
	"net"

	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/endpoint/connector"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
)

// DatapathConfiguration is the static configuration of the datapath. The
// configuration cannot change throughout the lifetime of a datapath object.
type DatapathConfiguration struct {
	// HostDevice is the name of the device to be used to access the host.
	HostDevice string
	// EncryptInterface is the name of the device to be used for direct ruoting encryption
	EncryptInterface string
}

type linuxDatapath struct {
	node           datapath.NodeHandler
	nodeAddressing datapath.NodeAddressing
	config         DatapathConfiguration

	// prefixLengths tracks a mapping from CIDR prefix length to the count
	// of rules that refer to that prefix length.
	prefixLengths *counter.PrefixLengthCounter
}

// NewDatapath creates a new Linux datapath
func NewDatapath(config DatapathConfiguration) datapath.Datapath {
	dp := &linuxDatapath{
		nodeAddressing: NewNodeAddressing(),
		config:         config,
	}

	dp.node = NewNodeHandler(config, dp.nodeAddressing)

	if config.EncryptInterface != "" {
		if err := connector.DisableRpFilter(config.EncryptInterface); err != nil {
			log.WithField(logfields.Interface, config.EncryptInterface).Warn("Rpfilter could not be disabled, node to node encryption may fail")
		}
	}

	dp.prefixLengths = newPrefixLengthCounter()

	return dp
}

func newPrefixLengthCounter() *counter.PrefixLengthCounter {
	prefixLengths4 := ipcachemap.IPCache.GetMaxPrefixLengths(false)
	prefixLengths6 := ipcachemap.IPCache.GetMaxPrefixLengths(true)
	counter := counter.NewPrefixLengthCounter(prefixLengths6, prefixLengths4)

	// This is a bit ugly, but there's not a great way to define an IPNet
	// without parsing strings, etc.
	defaultPrefixes := []*net.IPNet{
		// IPv4
		createIPNet(0, net.IPv4len*8),             // world
		createIPNet(net.IPv4len*8, net.IPv4len*8), // hosts

		// IPv6
		createIPNet(0, net.IPv6len*8),             // world
		createIPNet(net.IPv6len*8, net.IPv6len*8), // hosts
	}
	_, err := counter.Add(defaultPrefixes)
	if err != nil {
		log.WithError(err).Fatal("Failed to create default prefix lengths")
	}
	return counter
}

func createIPNet(ones, bits int) *net.IPNet {
	return &net.IPNet{
		Mask: net.CIDRMask(ones, bits),
	}
}

// Node returns the handler for node events
func (l *linuxDatapath) Node() datapath.NodeHandler {
	return l.node
}

// LocalNodeAddressing returns the node addressing implementation of the local
// node
func (l *linuxDatapath) LocalNodeAddressing() datapath.NodeAddressing {
	return l.nodeAddressing
}

func (l *linuxDatapath) InstallProxyRules(proxyPort uint16, ingress bool, name string) error {
	return iptables.InstallProxyRules(proxyPort, ingress, name)
}

func (l *linuxDatapath) RemoveProxyRules(proxyPort uint16, ingress bool, name string) error {
	return iptables.RemoveProxyRules(proxyPort, ingress, name)
}

func (l *linuxDatapath) PrefixLengthCounter() *counter.PrefixLengthCounter {
	return l.prefixLengths
}
