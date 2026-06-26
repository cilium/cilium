// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import "github.com/sirupsen/logrus"

var log = logrus.New()

// BasePath returns the base path of the Cilium source tree on the node.
func (s *SSHMeta) BasePath() string {
	return s.basePath
}
