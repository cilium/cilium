// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"net"
	"os"
	"strconv"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/daemon/defaults"
	"github.com/cilium/cilium/pkg/apisocket"
	"github.com/cilium/cilium/pkg/logfields"

	log "github.com/sirupsen/logrus"
)

const targetName = "cilium-node-monitor"

func main() {
	scopedLog := log.WithField(logfields.Path, defaults.MonitorSockPath)
	common.RequireRootPrivilege(targetName)
	os.Remove(defaults.MonitorSockPath)
	server, err := net.Listen("unix", defaults.MonitorSockPath)
	if err != nil {
		scopedLog.WithError(err).Fatal("Cannot listen on socket")
	}

	if os.Getuid() == 0 {
		err := apisocket.SetDefaultPermissions(defaults.MonitorSockPath)
		if err != nil {
			scopedLog.WithError(err).Fatal("Cannot set default permissions on socket")
		}
	}

	m := Monitor{}
	go m.handleConnection(server)
	npages := 64
	if len(os.Args) > 1 {
		v, err := strconv.Atoi(os.Args[1])
		if v > 0 {
			npages = v
		} else {
			log.WithError(err).Info("Cannot parse number of pages with strconv")
		}
	}
	m.Run(npages)
}
