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

package types

// Tags implements generic key value tags used by AWS
type Tags map[string]string

// Match returns true if the required tags are all found
func (t Tags) Match(required Tags) bool {
	for k, neededvalue := range required {
		haveValue, ok := t[k]
		if !ok || (ok && neededvalue != haveValue) {
			return false
		}
	}
	return true
}

// Subnet is a representation of an AWS subnet
type Subnet struct {
	// ID is the subnet ID
	ID string

	// Name is the subnet name
	Name string

	// CIDR is the CIDR associated with the subnet
	CIDR string

	// AvailabilityZone is the availability zone of the subnet
	AvailabilityZone string

	// VpcID is the VPC the subnet is in
	VpcID string

	// AvailableAddresses is the number of addresses available for
	// allocation
	AvailableAddresses int

	// Tags is the tags of the subnet
	Tags Tags
}

// Vpc is the representation of an AWS VPC
type Vpc struct {
	// ID is the VPC ID
	ID string

	// PrimaryCIDR is the primary IPv4 CIDR
	PrimaryCIDR string
}
