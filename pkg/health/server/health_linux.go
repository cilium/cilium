// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"strconv"

	"golang.org/x/sys/unix"

	healthModels "github.com/cilium/cilium/api/v1/health/models"
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
