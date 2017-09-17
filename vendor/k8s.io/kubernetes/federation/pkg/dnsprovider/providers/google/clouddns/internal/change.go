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

package internal

import (
	dns "google.golang.org/api/dns/v1"
	"k8s.io/kubernetes/federation/pkg/dnsprovider/providers/google/clouddns/internal/interfaces"
)

// Compile time check for interface adherence
var _ interfaces.Change = Change{}

type Change struct{ impl *dns.Change }

func (c Change) Additions() (rrsets []interfaces.ResourceRecordSet) {
	rrsets = make([]interfaces.ResourceRecordSet, len(c.impl.Additions))
	for index, addition := range c.impl.Additions {
		rrsets[index] = interfaces.ResourceRecordSet(&ResourceRecordSet{addition})
	}
	return rrsets
}

func (c Change) Deletions() (rrsets []interfaces.ResourceRecordSet) {
	rrsets = make([]interfaces.ResourceRecordSet, len(c.impl.Deletions))
	for index, deletion := range c.impl.Deletions {
		rrsets[index] = interfaces.ResourceRecordSet(&ResourceRecordSet{deletion})
	}
	return rrsets
}
