// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/health/client/connectivity"
)

type daemonHealthGetter interface {
	GetHealthz(params *daemon.GetHealthzParams, opts ...daemon.ClientOption) (*daemon.GetHealthzOK, error)
}

type connectivityStatusGetter interface {
	GetStatus(params *connectivity.GetStatusParams, opts ...connectivity.ClientOption) (*connectivity.GetStatusOK, error)
}
