// Copyright 2019 Authors of Hubble
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

package v1

const (
	// ObserverServiceName is the name of the observer service for the grpc health check
	ObserverServiceName = "hubble.server.Observer"

	// K8sNamespaceTag is the label tag which denotes the namespace.
	K8sNamespaceTag = "k8s:io.kubernetes.pod.namespace"
)
