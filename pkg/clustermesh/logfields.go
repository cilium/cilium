// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "clustermesh")

const (
	fieldClusterName   = "clusterName"
	fieldConfig        = "config"
	fieldConfigDir     = "configDir"
	fieldEvent         = "event"
	fieldKVStoreStatus = "kvstoreStatus"
	fieldKVStoreErr    = "kvstoreErr"
)
