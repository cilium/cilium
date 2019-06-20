/*
Copyright 2017 The Kubernetes Authors.

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

package features

import (
	"k8s.io/apimachinery/pkg/util/runtime"

	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/component-base/featuregate"
)

const (
	// Every feature gate should add method here following this template:
	//
	// // owner: @username
	// // alpha: v1.4
	// MyFeature() bool

	// owner: @tallclair
	// alpha: v1.5
	// beta: v1.6
	//
	// StreamingProxyRedirects controls whether the apiserver should intercept (and follow)
	// redirects from the backend (Kubelet) for streaming requests (exec/attach/port-forward).
	StreamingProxyRedirects featuregate.Feature = "StreamingProxyRedirects"

	// owner: @tallclair
	// alpha: v1.10
	// beta: v1.14
	//
	// ValidateProxyRedirects controls whether the apiserver should validate that redirects are only
	// followed to the same host. Only used if StreamingProxyRedirects is enabled.
	ValidateProxyRedirects featuregate.Feature = "ValidateProxyRedirects"

	// owner: @tallclair
	// alpha: v1.7
	// beta: v1.8
	// GA: v1.12
	//
	// AdvancedAuditing enables a much more general API auditing pipeline, which includes support for
	// pluggable output backends and an audit policy specifying how different requests should be
	// audited.
	AdvancedAuditing featuregate.Feature = "AdvancedAuditing"

	// owner: @pbarker
	// alpha: v1.13
	//
	// DynamicAuditing enables configuration of audit policy and webhook backends through an
	// AuditSink API object.
	DynamicAuditing featuregate.Feature = "DynamicAuditing"

	// owner: @ilackams
	// alpha: v1.7
	//
	// Enables compression of REST responses (GET and LIST only)
	APIResponseCompression featuregate.Feature = "APIResponseCompression"

	// owner: @smarterclayton
	// alpha: v1.8
	// beta: v1.9
	//
	// Allow API clients to retrieve resource lists in chunks rather than
	// all at once.
	APIListChunking featuregate.Feature = "APIListChunking"

	// owner: @apelisse
	// alpha: v1.12
	// beta: v1.13
	//
	// Allow requests to be processed but not stored, so that
	// validation, merging, mutation can be tested without
	// committing.
	DryRun featuregate.Feature = "DryRun"

	// owner: @caesarxuchao
	// alpha: v1.15
	//
	// Allow apiservers to show a count of remaining items in the response
	// to a chunking list request.
	RemainingItemCount featuregate.Feature = "RemainingItemCount"

	// owner: @apelisse, @lavalamp
	// alpha: v1.14
	//
	// Server-side apply. Merging happens on the server.
	ServerSideApply featuregate.Feature = "ServerSideApply"

	// owner: @caesarxuchao
	// alpha: v1.14
	// beta: v1.15
	//
	// Allow apiservers to expose the storage version hash in the discovery
	// document.
	StorageVersionHash featuregate.Feature = "StorageVersionHash"

	// owner: @ksubrmnn
	// alpha: v1.14
	//
	// Allows kube-proxy to run in Overlay mode for Windows
	WinOverlay featuregate.Feature = "WinOverlay"

	// owner: @ksubrmnn
	// alpha: v1.14
	//
	// Allows kube-proxy to create DSR loadbalancers for Windows
	WinDSR featuregate.Feature = "WinDSR"

	// owner: @wojtek-t
	// alpha: v1.15
	//
	// Enables support for watch bookmark events.
	WatchBookmark featuregate.Feature = "WatchBookmark"

	// owner: @MikeSpreitzer @yue9944882
	// alpha: v1.15
	//
	//
	// Enables managing request concurrency with prioritization and fairness at each server
	RequestManagement featuregate.Feature = "RequestManagement"
)

func init() {
	runtime.Must(utilfeature.DefaultMutableFeatureGate.Add(defaultKubernetesFeatureGates))
}

// defaultKubernetesFeatureGates consists of all known Kubernetes-specific feature keys.
// To add a new feature, define a key for it above and add it here. The features will be
// available throughout Kubernetes binaries.
var defaultKubernetesFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	StreamingProxyRedirects: {Default: true, PreRelease: featuregate.Beta},
	ValidateProxyRedirects:  {Default: true, PreRelease: featuregate.Beta},
	AdvancedAuditing:        {Default: true, PreRelease: featuregate.GA},
	DynamicAuditing:         {Default: false, PreRelease: featuregate.Alpha},
	APIResponseCompression:  {Default: false, PreRelease: featuregate.Alpha},
	APIListChunking:         {Default: true, PreRelease: featuregate.Beta},
	DryRun:                  {Default: true, PreRelease: featuregate.Beta},
	RemainingItemCount:      {Default: false, PreRelease: featuregate.Alpha},
	ServerSideApply:         {Default: false, PreRelease: featuregate.Alpha},
	StorageVersionHash:      {Default: true, PreRelease: featuregate.Beta},
	WinOverlay:              {Default: false, PreRelease: featuregate.Alpha},
	WinDSR:                  {Default: false, PreRelease: featuregate.Alpha},
	WatchBookmark:           {Default: false, PreRelease: featuregate.Alpha},
	RequestManagement:       {Default: false, PreRelease: featuregate.Alpha},
}
