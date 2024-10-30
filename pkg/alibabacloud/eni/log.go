// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultSlogLogger.With(logfields.LogSubsys, "eni")
)

const (
	fieldENIID = "eniID"
)
