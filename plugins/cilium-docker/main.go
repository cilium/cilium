// Copyright 2016-2017 Authors of Cilium
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
	"fmt"
	"os"
	"path"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/plugins/cilium-docker/driver"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	pluginPath string
	driverSock string
	debug      bool
	ciliumAPI  string
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "cilium-docker",
	Short: "Cilium plugin for Docker (libnetwork)",
	Long: `Cilium plugin for Docker (libnetwork)

Docker plugin implementing the networking and IPAM API.

The plugin handles requests from the local Docker runtime to provide
network connectivity and IP address management for containers that are
connected to a Docker network of type "cilium".`,
	Example: `  docker network create my_network --ipam-driver cilium --driver cilium
  docker run --net my_network hello-world
`,
	Run: func(cmd *cobra.Command, args []string) {
		if d, err := driver.NewDriver(ciliumAPI); err != nil {
			log.Fatalf("Unable to create cilium-net driver: %s", err)
		} else {
			log.Infof("Listening for events from Docker on %s", driverSock)
			if err := d.Listen(driverSock); err != nil {
				log.Fatal(err)
			}
		}
	},
}

func main() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	flags := RootCmd.PersistentFlags()
	flags.BoolVarP(&debug, "debug", "D", false, "Enable debug messages")
	flags.StringVar(&ciliumAPI, "cilium-api", "", "URI to server-side API")
	flags.StringVar(&pluginPath, "docker-plugins", "/run/docker/plugins",
		"Path to Docker plugins directory")
}

func initConfig() {
	if debug {
		common.SetupLogging([]string{"syslog"}, map[string]string{"syslog.level": "debug"}, "cilium-docker", true)
	} else {
		common.SetupLogging([]string{"syslog"}, map[string]string{"syslog.level": "info"}, "cilium-docker", false)
	}

	// The cilium-docker plugin must be run as root user.
	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "Please run the cilium-docker plugin with root privileges.\n")
		os.Exit(1)
	}

	driverSock = path.Join(pluginPath, "cilium.sock")

	if err := os.MkdirAll(pluginPath, 0755); err != nil && !os.IsExist(err) {
		log.Fatalf("Could not create net plugin path directory: %s", err)
	}

	if _, err := os.Stat(driverSock); err == nil {
		log.Debugf("socket file %s already exists, unlinking the old file handle.", driverSock)
		os.RemoveAll(driverSock)
	}
}
