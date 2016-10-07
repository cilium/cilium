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

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/plugins/cilium-docker/driver"

	"github.com/codegangsta/cli"
	l "github.com/op/go-logging"
)

const (
	// PluginPath is the docker plugins directory where docker plugin is present.
	pluginPath = "/run/docker/plugins/"
	// driverSock is the cilium socket for the communication between docker and cilium.
	driverSock = pluginPath + "cilium.sock"
)

var log = l.MustGetLogger("cilium-net-docker-plugin")

func main() {
	app := cli.NewApp()
	app.Name = "cilium-net"
	app.Usage = "Cilium Networking Docker Plugin"
	app.Version = common.Version
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug, D",
			Usage: "Enable debug messages",
		},
	}
	app.Before = initEnv
	app.Action = run
	app.Run(os.Args)
}

func initEnv(ctx *cli.Context) error {
	if ctx.Bool("debug") {
		common.SetupLOG(log, "DEBUG")
	} else {
		common.SetupLOG(log, "INFO")
	}

	if err := os.MkdirAll(pluginPath, 0755); err != nil && !os.IsExist(err) {
		log.Fatalf("Could not create net plugin path directory: %s", err)
	}

	if _, err := os.Stat(driverSock); err == nil {
		log.Debugf("socket file %s already exists, unlinking the old file handle.", driverSock)
		os.RemoveAll(driverSock)
	}

	log.Debugf("The plugin absolute path and handle is %s", driverSock)

	return nil
}

func run(ctx *cli.Context) {
	d, err := driver.NewDriver(ctx)
	if err != nil {
		log.Fatalf("Unable to create cilium-net driver: %s", err)
	}

	log.Info("Cilium networking Docker plugin ready")

	if err := d.Listen(driverSock); err != nil {
		log.Fatal(err)
	}
}
