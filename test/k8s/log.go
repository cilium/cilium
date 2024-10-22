// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging"
)

var log = logging.DefaultLogger
var logger = logrus.NewEntry(log)
