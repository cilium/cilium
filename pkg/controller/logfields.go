// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controller

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// logging field definitions
const (
	// fieldControllerName is the name of the controller
	fieldControllerName = "name"

	// fieldUUID is the UUID of the controller
	fieldUUID = "uuid"

	// fieldConsecutiveErrors is the number of consecutive errors of a controller
	fieldConsecutiveErrors = "consecutiveErrors"
)

var (
	// log is the controller package logger object.
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "controller")
)
