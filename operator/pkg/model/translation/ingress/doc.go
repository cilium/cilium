// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package ingress contains the translation logic from Ingress to CiliumEnvoyConfig
// and related resources.
package ingress

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ingress-controller")
