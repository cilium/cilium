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
	"github.com/cilium/cilium/common/bpf"
)

const (
	// Maximum number of entries in each hashtable
	maxEntries = 65536
)

// Interface describing protocol independent key for services map
type ServiceKey interface {
	bpf.MapKey

	// Returns true if the key is of type IPv6
	IsIPv6() bool

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// Returns a RevNatValue matching a ServiceKey
	RevNatValue() RevNatValue
}

// Interface describing protocol independent value for services map
type ServiceValue interface {
	bpf.MapValue

	// Returns a RevNatKey matching a ServiceValue
	RevNatKey() RevNatKey
}

func UpdateService(key ServiceKey, value ServiceValue) error {
	return key.Map().Update(key, value)
}

func DeleteService(key ServiceKey) error {
	return key.Map().Delete(key)
}

func LookupService(key ServiceKey) (bpf.MapValue, error) {
	return key.Map().Lookup(key)
}

type RevNatKey interface {
	bpf.MapKey

	// Returns true if the key is of type IPv6
	IsIPv6() bool

	// Returns the BPF map matching the key type
	Map() *bpf.Map
}

type RevNatValue interface {
	bpf.MapValue
}

func UpdateRevNat(key RevNatKey, value RevNatValue) error {
	return key.Map().Update(key, value)
}

func DeleteRevNat(key RevNatKey) error {
	return key.Map().Delete(key)
}

func LookupRevNat(key RevNatKey) (RevNatValue, error) {
	return key.Map().Lookup(key)
}
