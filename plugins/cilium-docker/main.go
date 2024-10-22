// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/plugins/cilium-docker/driver"
)

var (
	log            = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-docker")
	pluginPath     string
	driverSock     string
	debug          bool
	ciliumAPI      string
	dockerHostPath string
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
		common.RequireRootPrivilege("cilium-docker")

		createPluginSock()

		if d, err := driver.NewDriver(ciliumAPI, dockerHostPath); err != nil {
			log.WithError(err).Fatal("Unable to create cilium-net driver")
		} else {
			log.WithField(logfields.Path, driverSock).Info("Listening for events from Docker")
			if err := d.Listen(driverSock); err != nil {
				log.Fatal(err)
			}
		}
	},
}

func main() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	flags := RootCmd.PersistentFlags()
	flags.BoolVarP(&debug, "debug", "D", false, "Enable debug messages")
	flags.StringVar(&ciliumAPI, "cilium-api", "", "URI to server-side API")
	flags.StringVar(&dockerHostPath, "docker-host-path", "unix:///var/run/docker.sock", "Docker socket")
	flags.StringVar(&pluginPath, "docker-plugins", "/run/docker/plugins",
		"Path to Docker plugins directory")
}

func initConfig() {
	if debug {
		log.Logger.SetLevel(logrus.DebugLevel)
	} else {
		log.Logger.SetLevel(logrus.InfoLevel)
	}
}

func createPluginSock() {
	driverSock = filepath.Join(pluginPath, "cilium.sock")

	if err := os.MkdirAll(pluginPath, 0755); err != nil && !os.IsExist(err) {
		log.WithError(err).Fatal("Could not create net plugin path directory")
	}

	if _, err := os.Stat(driverSock); err == nil {
		log.WithField(logfields.Path, driverSock).Debug("socket file already exists, unlinking the old file handle.")
		os.RemoveAll(driverSock)
	}
}
