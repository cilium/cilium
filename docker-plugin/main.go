package main

import (
	log "github.com/Sirupsen/logrus"
	"github.com/cilium-team/cilium-net/docker-plugin/driver"
	"github.com/codegangsta/cli"
	"os"
)

const pluginPath = "/run/docker/plugins/"
const driverPath = pluginPath + "cilium.sock"

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

	if err := os.MkdirAll(pluginPath, 0755); err != nil && !os.IsExist(err) {
		log.Fatalf("Could not create net plugin path directory: %s", err)
	}

	if _, err := os.Stat(driverPath); err == nil {
		log.Debugf("socket file %s already exists, unlinking the old file handle.", driverPath)
		os.RemoveAll(driverPath)
	}

	log.Debugf("The plugin absolute path and handle is %s", driverPath)

	return nil
}

func Run(ctx *cli.Context) {
	d, err := driver.New(ctx)
	if err != nil {
		log.Fatalf("Unable to create cilium-net driver: %s", err)
	}

	log.Info("Cilium networking Docker plugin ready")

	if err := d.Listen(driverPath); err != nil {
		log.Fatal(err)
	}
}
