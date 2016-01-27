package main

import (
	"os"

	common "github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/docker-plugin/driver"

	log "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/Sirupsen/logrus"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/codegangsta/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "cilium-net"
	app.Usage = "Cilium Networking Docker Plugin"
	app.Version = "0.1.0"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "node-addr, n",
			Usage: "Address of the compute node",
		},
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "Enable debug messages",
		},
	}
	app.Before = initEnv
	app.Action = Run
	app.Run(os.Args)
}

func initEnv(ctx *cli.Context) error {
	if ctx.Bool("debug") {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	log.SetOutput(os.Stderr)

	if err := os.MkdirAll(common.PluginPath, 0755); err != nil && !os.IsExist(err) {
		log.Fatalf("Could not create net plugin path directory: %s", err)
	}

	if _, err := os.Stat(common.DriverSock); err == nil {
		log.Debugf("socket file %s already exists, unlinking the old file handle.", common.DriverSock)
		os.RemoveAll(common.DriverSock)
	}

	log.Debugf("The plugin absolute path and handle is %s", common.DriverSock)

	return nil
}

func Run(ctx *cli.Context) {
	d, err := driver.NewDriver(ctx)
	if err != nil {
		log.Fatalf("Unable to create cilium-net driver: %s", err)
	}

	log.Info("Cilium networking Docker plugin ready")

	if err := d.Listen(common.DriverSock); err != nil {
		log.Fatal(err)
	}
}
