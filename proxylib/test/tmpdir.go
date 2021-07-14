// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package test

import (
	"os"

	log "github.com/sirupsen/logrus"
)

var Tmpdir string

func init() {
	var err error
	Tmpdir, err = os.MkdirTemp("", "cilium_envoy_go_test")
	if err != nil {
		log.Fatal("Failed to create a temporaty directory for testing")
	}
}
