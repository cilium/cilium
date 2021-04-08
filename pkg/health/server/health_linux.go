// Copyright 2017-2021 Authors of Cilium
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

package server

import (
	"strconv"

	healthModels "github.com/cilium/cilium/api/v1/health/models"

	"golang.org/x/sys/unix"
)

func dumpLoad() (*healthModels.LoadResponse, error) {
	var info unix.Sysinfo_t
	err := unix.Sysinfo(&info)
	if err != nil {
		return nil, err
	}

	scale := float64(1 << unix.SI_LOAD_SHIFT)
	return &healthModels.LoadResponse{
		Last1min:  strconv.FormatFloat(float64(info.Loads[0])/scale, 'f', 2, 64),
		Last5min:  strconv.FormatFloat(float64(info.Loads[1])/scale, 'f', 2, 64),
		Last15min: strconv.FormatFloat(float64(info.Loads[2])/scale, 'f', 2, 64),
	}, nil
}
