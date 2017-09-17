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

package route53

import (
	"k8s.io/kubernetes/federation/pkg/dnsprovider"
	"k8s.io/kubernetes/federation/pkg/dnsprovider/providers/aws/route53/stubs"
)

// Compile time check for interface adherence
var _ dnsprovider.Interface = Interface{}

type Interface struct {
	service stubs.Route53API
}

// New builds an Interface, with a specified Route53API implementation.
// This is useful for testing purposes, but also if we want an instance with with custom AWS options.
func New(service stubs.Route53API) *Interface {
	return &Interface{service}
}

func (i Interface) Zones() (zones dnsprovider.Zones, supported bool) {
	return Zones{&i}, true
}
