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

package types

import (
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

// SecurityGroup is the representation of an AlibabaCloud Security Group
//
// +k8s:deepcopy-gen=true
type SecurityGroup struct {
	// ID is the SecurityGroup ID
	ID string

	// VPCID is the VPC ID in which the security group resides
	VPCID string

	// Tags are the tags of the security group
	Tags ipamTypes.Tags
}

// SecurityGroupMap indexes Security Groups by security group ID
type SecurityGroupMap map[string]*SecurityGroup
