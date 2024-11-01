// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package defaults

import (
	"os"
	"path/filepath"
	"time"
)

const (
	// ServerAddress is the default server address.
	ServerAddress = "localhost:4245"

	// DialTimeout is the default timeout for dialing the server.
	DialTimeout = 5 * time.Second

	// RequestTimeout is the default timeout for client requests.
	RequestTimeout = 12 * time.Second

	// FlowPrintCount is the default number of flows to print on the hubble
	// observe CLI.
	FlowPrintCount = 20

	// EventsPrintCount is the default number of agent/debug events to print
	// on the hubble events CLI.
	EventsPrintCount = 20

	// TargetTLSPrefix is a scheme that indicates that the target connection
	// requires TLS.
	TargetTLSPrefix = "tls://"
)

var (
	// ConfigDir is the default directory path to store Hubble
	// configuration files. It may be unset.
	ConfigDir string
	// ConfigDirFallback is the directory path to store Hubble configuration
	// files if defaultConfigDir is unset. Note that it may also be unset.
	ConfigDirFallback string
	// ConfigFile is the path to an optional configuration file.
	// It may be unset.
	ConfigFile string

	// FieldMask is a list of requested fields when using "dict", "tab", or "compact"
	// output format and no custom mask is specified.
	FieldMask = []string{"time", "source.identity", "source.namespace", "source.pod_name", "destination.identity", "destination.namespace", "destination.pod_name", "source_service", "destination_service", "l4", "IP", "ethernet", "l7", "Type", "node_name", "is_reply", "event_type", "verdict", "Summary"}
)

func init() {
	// honor user config dir
	if dir, err := os.UserConfigDir(); err == nil {
		ConfigDir = filepath.Join(dir, "hubble")
	}
	// fallback to home directory
	if dir, err := os.UserHomeDir(); err == nil {
		ConfigDirFallback = filepath.Join(dir, ".hubble")
	}

	switch {
	case ConfigDir != "":
		ConfigFile = filepath.Join(ConfigDir, "config.yaml")
	case ConfigDirFallback != "":
		ConfigFile = filepath.Join(ConfigDirFallback, "config.yaml")
	}
}
