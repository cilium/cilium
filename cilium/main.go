package main

import (
	"os"

	daemon "github.com/noironetworks/cilium-net/cilium-net-daemon"
	endpoint "github.com/noironetworks/cilium-net/cilium/endpoint"
	"github.com/noironetworks/cilium-net/cilium/monitor"
	policy "github.com/noironetworks/cilium-net/cilium/policy"
	"github.com/noironetworks/cilium-net/common"

	"github.com/codegangsta/cli"
	l "github.com/op/go-logging"
)

var (
	log = l.MustGetLogger("cilium-net-policy-repo")
)

func main() {
	app := cli.NewApp()
	app.Name = "cilium"
	app.Usage = "Cilium"
	app.Version = "0.1.0"
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
