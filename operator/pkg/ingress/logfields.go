// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const Subsys = "ingress-controller"
const CiliumIngressClassIsDefault = "cilium-is-default"

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, Subsys)
