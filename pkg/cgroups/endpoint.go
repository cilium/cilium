// Copyright 2020 Authors of Cilium
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

package cgroups

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"sync"

	"github.com/cilium/cilium/pkg/bandwidth"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
)

var (
	classBaseName = "net_cls.classid"

	checkCgroupV2Once   sync.Once
	cgroupV2PerEndpoint bool
)

// perEndpointIDExists returns true if the cgroup v2 id appears to be available
// for use in the datapath. If not available, we assume that cgroup v1 net_cls
// controller is available for each endpoint.
func perEndpointIDExists() bool {
	checkCgroupV2Once.Do(func() {
		path := fmt.Sprintf("%s/kubepods", GetCgroupRootV2())
		if _, err := os.Stat(path); err != nil {
			cgroupV2PerEndpoint = false
			return
		}
		if option.Config.EnableBandwidthManager {
			log.Warningf("Pods are managed under cgroup v2. Pod's %s annotation not (yet) supported",
				bandwidth.EgressBandwidth)
		}
		cgroupV2PerEndpoint = true
	})
	return cgroupV2PerEndpoint
}

type endpoint interface {
	Cgroup() string
	GetID16() uint16
}

func ConfigureEndpoint(ep endpoint) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.EndpointID: ep.GetID16(),
	})
	if perEndpointIDExists() || ep.Cgroup() == "" {
		return nil
	}
	classID := fmt.Sprintf("%d", ep.GetID16())
	for _, mount := range getCgroupNetMounts() {
		fullPath := path.Join(mount, ep.Cgroup(), classBaseName)
		if err := ioutil.WriteFile(fullPath, []byte(classID), 0755); err != nil {
			scopedLog.WithFields(logrus.Fields{
				"cgroup": fullPath,
			}).WithError(err).Warning("Tagging cgroup v1 failed")
			return err
		}
		content, err := ioutil.ReadFile(fullPath)
		if err != nil || string(content[:len(content)-1]) != classID {
			scopedLog.WithFields(logrus.Fields{
				"got":      string(content),
				"expected": string(classID),
			}).WithError(err).Warning("Validate of cgroup configuration failed")
		}
	}
	return nil
}
