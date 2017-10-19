// Copyright 2017 Authors of Cilium
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

// Package logfields defines common logging fields which are used across packages
package logfields

const (
	// EndpointID is the numeric endpoint identifier
	EndpointID = "endpointID"

	// ContainerID is the container identifier
	ContainerID = "containerID"

	// IdentityLabels are the labels relevant for the security identity
	IdentityLabels = "identityLabels"

	// Identity is the identifier of a security identity
	Identity = "identity"

	// L3PolicyID is the identifier of a L3 Policy
	L3PolicyID = "policyID.L3"

	// L4PolicyID is the identifier of a L4 Policy
	L4PolicyID = "PolicyID.L4"

	// Path is a filesystem path. It can be a file or directory
	// REVIEW Should this match pkg/proxy/accesslog.FieldFilePath ?
	Path = "path"

	// IPAddr is an IPV4 or IPv6 address
	IPAddr = "ipAddr"

	// V4Prefix is a IPv4 subnet/CIDR prefix
	V4Prefix = "v4Prefix"

	// V6Prefix is a IPv6 subnet/CIDR prefix
	V6Prefix = "v6Prefix"

	K8sPodName            = "k8sPodName"
	K8sNamespace          = "k8sNamespace"
	K8sIdentityAnnotation = "k8sIdentityAnnotation" // REVIEW Reconcile this with orchestrationLabels
)
