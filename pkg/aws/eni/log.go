// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	subsysLogAttr = slog.String(logfields.LogSubsys, "eni")
)

const (
	fieldEniID = "eniID"
)
