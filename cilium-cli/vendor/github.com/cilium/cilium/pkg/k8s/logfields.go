// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// logging field definitions
const (
	// subsysK8s is the value for logfields.LogSubsys
	subsysK8s = "k8s"
)

var (
	// log is the k8s package logger object.
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)
)
