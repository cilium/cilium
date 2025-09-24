/*
Copyright 2024 The Kubernetes Authors.

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

package consts

const (
	// BundleVersionAnnotation is the annotation key used in the Gateway API CRDs to specify
	// the installed Gateway API version.
	BundleVersionAnnotation = "gateway.networking.k8s.io/bundle-version"

	// ChannelAnnotation is the annotation key used in the Gateway API CRDs to specify
	// the installed Gateway API channel.
	ChannelAnnotation = "gateway.networking.k8s.io/channel"

	// BundleVersion is the value used for the "gateway.networking.k8s.io/bundle-version" annotation.
	// These value must be updated during the release process.
	BundleVersion = "v1.4.0-rc.2"

	// ApprovalLink is the value used for the "api-approved.kubernetes.io" annotation.
	// These value must be updated during the release process.
	ApprovalLink = "https://github.com/kubernetes-sigs/gateway-api/pull/3328"
)
