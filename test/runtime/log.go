// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package RuntimeTest

import (
	"github.com/sirupsen/logrus"
)

var log = logrus.New()
var logger = logrus.NewEntry(log)
