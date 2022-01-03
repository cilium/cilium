// SPDX-License-Identifier: Apache-2.0
// Copyright 2017 Authors of Cilium

package RuntimeTest

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging"
)

var log = logging.DefaultLogger
var logger = logrus.NewEntry(log)
