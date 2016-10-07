//
// Copyright 2016 Authors of Cilium
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
//
package main

import (
	"os"

	endpoint "github.com/cilium/cilium/cilium/endpoint"
	"github.com/cilium/cilium/cilium/lb"
	"github.com/cilium/cilium/cilium/monitor"
	policy "github.com/cilium/cilium/cilium/policy"
	"github.com/cilium/cilium/common"
	daemon "github.com/cilium/cilium/daemon"

	"github.com/codegangsta/cli"
	l "github.com/op/go-logging"
)

var (
	log = l.MustGetLogger("cilium-cli")
)

func main() {
	app := cli.NewApp()
	app.Name = "cilium"
	app.Usage = "Cilium"
	app.Version = common.Version
	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug, D",
			Usage: "Enable debug messages",
		},
		cli.StringFlag{
			Name:  "host, H",
			Usage: "Daemon host to connect to",
		},
	}
	app.Commands = []cli.Command{
		daemon.CliCommand,
		policy.CliCommand,
		endpoint.CliCommand,
		monitor.CliCommand,
		lb.CliCommand,
	}
	app.Before = initEnv
	app.Run(os.Args)
}

func initEnv(ctx *cli.Context) error {
	if ctx.Bool("debug") {
		common.SetupLOG(log, "DEBUG")
	} else {
		common.SetupLOG(log, "INFO")
	}
	return nil
}
