// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	Subsys = "gateway-controller"

	gatewayClass = "gatewayClass"
	gateway      = "gateway"
	httpRoute    = "httpRoute"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, Subsys)
