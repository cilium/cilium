// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package cmd

import (
	"github.com/cilium/cilium/operator/option"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	operatorAddr string

	log = logrus.New()
)

// Populate options required by cilium-operator command line only.
func Populate() {
	operatorAddr = viper.GetString(option.OperatorAPIServeAddr)
}
