// SPDX-License-Identifier: Apache-2.0
// Copyright 2017 Authors of Cilium

package k8sTest

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger
var logger = logrus.NewEntry(log)
