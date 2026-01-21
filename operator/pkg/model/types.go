// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

// ServerHeaderTransformation controls how Envoy handles the HTTP Server header.
type ServerHeaderTransformation string

const (
	// ServerHeaderTransformationOverwrite overwrites any Server header with "envoy".
	ServerHeaderTransformationOverwrite ServerHeaderTransformation = "OVERWRITE"

	// ServerHeaderTransformationAppendIfAbsent appends Server "envoy" if no Server header is present.
	// If a Server header is present, passes it through.
	ServerHeaderTransformationAppendIfAbsent ServerHeaderTransformation = "APPEND_IF_ABSENT"

	// ServerHeaderTransformationPassThrough passes through the value of the server header,
	// and does not append a header if none is present.
	ServerHeaderTransformationPassThrough ServerHeaderTransformation = "PASS_THROUGH"
)
