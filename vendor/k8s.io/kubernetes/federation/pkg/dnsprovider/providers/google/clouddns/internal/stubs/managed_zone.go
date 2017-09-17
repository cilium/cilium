/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package stubs

import "k8s.io/kubernetes/federation/pkg/dnsprovider/providers/google/clouddns/internal/interfaces"

// Compile time check for interface adherence
var _ interfaces.ManagedZone = ManagedZone{}

type ManagedZone struct {
	Service *ManagedZonesService
	Name_   string
	Id_     uint64
	Rrsets  []ResourceRecordSet
}

func (m ManagedZone) Name() string {
	return m.Name_
}

func (m ManagedZone) Id() uint64 {
	return m.Id_
}

func (m ManagedZone) DnsName() string {
	return m.Name_ // Don't bother storing a separate DNS name
}
