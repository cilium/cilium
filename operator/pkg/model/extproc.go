// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

const (
	// ExtProcFilterNamePrefix is the Envoy well-known name for the ext_proc HTTP filter.
	// Filter instance names are built as "<prefix>/<namespace>/<crdName>".
	ExtProcFilterNamePrefix = "envoy.filters.http.ext_proc"

	// ExtProcExternalProcessorTypeURL is the protobuf type URL for the ExternalProcessor
	// filter config. Used when populating ExtensionRefFilter.TypeURL at ingestion time.
	ExtProcExternalProcessorTypeURL = "type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor"

	// ExtProcPerRouteTypeURL is the protobuf type URL for ExtProcPerRoute, used as the
	// TypedPerFilterConfig value on individual routes to enable or disable the filter.
	ExtProcPerRouteTypeURL = "type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExtProcPerRoute"
)
