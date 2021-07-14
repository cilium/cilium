// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2019 Authors of Cilium

package logging

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func init() {
	flags := flag.NewFlagSet("init-debug", flag.ContinueOnError)
	flags.Usage = func() {}
	flags.SetOutput(io.Discard)

	debug := flags.Bool("debug", false, "")
	flags.Parse(os.Args)

	if *debug || viper.GetBool("debug") {
		DefaultLogger.SetLevel(logrus.DebugLevel)
	}
}
