package config

import (
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/sirupsen/logrus"
)

// EndpointConfig provides access to EndpointConfig information that is necessary to
// compile and load the datapath.
type EndpointConfig interface {
	datapath.EndpointConfiguration
	InterfaceName() string
	Logger(subsystem string) *logrus.Entry
	StateDir() string
	MapPath() string
}
