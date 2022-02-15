// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

import "github.com/sirupsen/logrus"

// Endpoint provides access endpoint configuration information that is necessary
// to compile and load the datapath.
type Endpoint interface {
	EndpointConfiguration
	InterfaceName() string
	Logger(subsystem string) *logrus.Entry
	StateDir() string
	MapPath() string
}
