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
package lbmap

import (
	"net"

	"github.com/cilium/cilium/common/bpf"
)

const (
	// Maximum number of entries in each hashtable
	maxEntries = 65536
)

// Interface describing protocol independent key for services map
type ServiceKey interface {
	bpf.MapKey

	// Returns human readable string representation
	String() string

	// Returns true if the key is of type IPv6
	IsIPv6() bool

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// Returns a RevNatValue matching a ServiceKey
	RevNatValue() RevNatValue

	// Returns the port set in the key or 0
	GetPort() uint16

	// Set the backend index (master: 0, backend: nth backend)
	SetBackend(int)

	// Return backend index
	GetBackend() int

	// Convert between host byte order and map byte order
	Convert() ServiceKey
}

// Interface describing protocol independent value for services map
type ServiceValue interface {
	bpf.MapValue

	// Returns human readable string representation
	String() string

	// Returns a RevNatKey matching a ServiceValue
	RevNatKey() RevNatKey

	// Set the number of backends
	SetCount(int)

	// Get the number of backends
	GetCount() int

	// Set address to map to (left blank for master)
	SetAddress(net.IP) error

	// Set port to map to (left blank for master)
	SetPort(uint16)

	// Set reverse NAT identifier
	SetRevNat(int)

	// Convert between host byte order and map byte order
	Convert() ServiceValue
}

func UpdateService(key ServiceKey, value ServiceValue) error {
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.Convert(), value.Convert())
}

func DeleteService(key ServiceKey) error {
	return key.Map().Delete(key.Convert())
}

func LookupService(key ServiceKey) (ServiceValue, error) {
	var svc ServiceValue

	val, err := key.Map().Lookup(key.Convert())
	if err != nil {
		return nil, err
	}

	if key.IsIPv6() {
		svc = val.(*Service6Value)
	} else {
		svc = val.(*Service4Value)
	}

	return svc.Convert(), nil
}

type RevNatKey interface {
	bpf.MapKey

	// Returns true if the key is of type IPv6
	IsIPv6() bool

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// Convert between host byte order and map byte order
	Convert() RevNatKey
}

type RevNatValue interface {
	bpf.MapValue

	// Convert between host byte order and map byte order
	Convert() RevNatValue
}

func UpdateRevNat(key RevNatKey, value RevNatValue) error {
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.Convert(), value.Convert())
}

func DeleteRevNat(key RevNatKey) error {
	return key.Map().Delete(key.Convert())
}

func LookupRevNat(key RevNatKey) (RevNatValue, error) {
	var revnat RevNatValue

	val, err := key.Map().Lookup(key.Convert())
	if err != nil {
		return nil, err
	}

	if key.IsIPv6() {
		revnat = val.(*RevNat6Value)
	} else {
		revnat = val.(*RevNat4Value)
	}

	return revnat.Convert(), nil
}
