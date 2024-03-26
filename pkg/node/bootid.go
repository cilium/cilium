// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import "sync"

var (
	localBootID string
	logOnce     sync.Once
)

func GetBootID() string {
	logOnce.Do(func() {
		log.Infof("Local boot ID is %q", localBootID)
	})
	return localBootID
}
