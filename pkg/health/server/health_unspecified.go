// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2021 Authors of Cilium

// +build !linux

package server

import (
	"errors"

	healthModels "github.com/cilium/cilium/api/v1/health/models"
)

func dumpLoad() (*healthModels.LoadResponse, error) {
	return nil, errors.New("not implemented")
}
