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
package daemon

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	common "github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	cnc "github.com/cilium/cilium/common/client"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/daemon/daemon"
	s "github.com/cilium/cilium/daemon/server"

	"github.com/codegangsta/cli"
	etcdAPI "github.com/coreos/etcd/clientv3"
	consulAPI "github.com/hashicorp/consul/api"
	"github.com/op/go-logging"
)

var (
	config = daemon.NewConfig()

	// Arguments variables keep in alphabetical order
	consulAddr         string
	disableConntrack   bool
	disablePolicy      bool
	enableTracing      bool
	enableLogstash     bool
	etcdAddr           cli.StringSlice
	labelPrefixFile    string
	logstashAddr       string
	logstashProbeTimer int
	socketPath         string
	uiServerAddr       string
	v4Prefix           string
	v6Address          string
	nat46prefix        string

	log = logging.MustGetLogger("cilium-net-daemon")

	// CliCommand is the command that will be used in cilium-net main program.
	CliCommand cli.Command
)

func init() {
	CliCommand = cli.Command{
		Name: "daemon",
		// Keep Destination alphabetical order
		Subcommands: []cli.Command{
			{
				Name:   "run",
				Usage:  "Run the daemon",
				Before: initEnv,
				Action: run,
				Flags: []cli.Flag{
					cli.StringFlag{
						Destination: &consulAddr,
						Name:        "consul-server, c",
						Usage:       "Consul agent address [127.0.0.1:8500]",
					},
					cli.StringFlag{
						Destination: &config.Device,
						Name:        "snoop-device, d",
						Value:       "undefined",
						Usage:       "Device to snoop on",
					},
					cli.BoolFlag{
						Destination: &disableConntrack,
						Name:        "disable-conntrack",
						Usage:       "Disable connection tracking",
					},
					cli.BoolFlag{
						Destination: &disablePolicy,
						Name:        "disable-policy",
						Usage:       "Disable policy enforcement",
					},
					cli.StringFlag{
						Destination: &config.DockerEndpoint,
						Name:        "e",
						Value:       "unix:///var/run/docker.sock",
						Usage:       "Register a listener for docker events on the given endpoint",
					},
					cli.StringSliceFlag{
						Value: &etcdAddr,
						Name:  "etcd-servers",
						Usage: "Etcd agent address [http://127.0.0.1:2379]",
					},
					cli.StringFlag{
						Destination: &config.EtcdCfgPath,
						Name:        "etcd-config-path",
						Usage:       "Absolute path to the etcd configuration file",
					},
					cli.BoolFlag{
						Destination: &enableTracing,
						Name:        "enable-tracing",
						Usage:       "Enable tracing while determining policy",
					},
					cli.StringFlag{
						Destination: &nat46prefix,
						Name:        "nat46-range",
						Value:       addressing.DefaultNAT46Prefix,
						Usage:       "IPv6 prefix to map IPv4 addresses to",
					},
					cli.StringFlag{
						Destination: &config.K8sEndpoint,
						Name:        "k8s-api-server, k",
						Usage:       "Kubernetes api address server",
					},
					cli.StringFlag{
						Destination: &config.K8sCfgPath,
						Name:        "k8s-kubeconfig-path",
						Usage:       "Absolute path to the kubeconfig file",
					},
					cli.BoolTFlag{
						Destination: &config.KeepConfig,
						Name:        "keep-config",
						Usage:       "When restoring state, keeps containers' configuration in place",
					},
					cli.StringFlag{
						Destination: &labelPrefixFile,
						Name:        "p",
						Value:       "",
						Usage:       "File with valid label prefixes",
					},
					cli.StringFlag{
						Destination: &config.LibDir,
						Name:        "D",
						Value:       common.DefaultLibDir,
						Usage:       "Cilium library directory",
					},
					cli.BoolFlag{
						Destination: &enableLogstash,
						Name:        "logstash",
						Usage:       "Enables logstash agent",
					},
					cli.StringFlag{
						Destination: &logstashAddr,
						Name:        "logstash-agent",
						Value:       "127.0.0.1:8080",
						Usage:       "Logstash agent address",
					},
					cli.IntFlag{
						Destination: &logstashProbeTimer,
						Name:        "logstash-probe-timer",
						Value:       10,
						Usage:       "Logstash probe timer (seconds)",
					},
					cli.StringFlag{
						Destination: &v6Address,
						Name:        "n, node-address",
						Value:       "",
						Usage:       "IPv6 address of node, must be in correct format",
					},
					cli.BoolTFlag{
						Destination: &config.RestoreState,
						Name:        "restore",
						Usage:       "Restores state, if possible, from previous daemon",
					},
					cli.StringFlag{
						Destination: &config.RunDir,
						Name:        "R",
						Value:       common.CiliumPath,
						Usage:       "Runtime data directory",
					},
					cli.StringFlag{
						Destination: &socketPath,
						Name:        "s",
						Value:       common.CiliumSock,
						Usage:       "Sets the socket path to listen for connections",
					},
					cli.StringFlag{
						Destination: &uiServerAddr,
						Name:        "ui-addr",
						Value:       "tcp://0.0.0.0:8080",
						Usage:       "IP address and port for UI server",
					},
					cli.BoolFlag{
						Destination: &config.UIEnabled,
						Name:        "ui",
						Usage:       "Enables cilium web UI",
					},
					cli.BoolFlag{
						Destination: &config.LBMode,
						Name:        "lb",
						Usage:       "Enables load balancer mode where load balancer bpf program is attached to the interface ",
					},
					cli.BoolFlag{
						Destination: &config.IPv4Enabled,
						Name:        "ipv4",
						Usage:       "Enables IPv4 mode where containers receive an IPv4 address ",
					},
					cli.StringFlag{
						Destination: &v4Prefix,
						Name:        "ipv4-range",
						Value:       "",
						Usage:       "IPv4 prefix",
					},
					cli.StringFlag{
						Destination: &config.Tunnel,
						Name:        "t",
						Value:       "vxlan",
						Usage:       "Tunnel mode vxlan or geneve, vxlan is the default",
					},
				},
			},
			{
				Name:      "config",
				Usage:     "Manage daemon configuration",
				Action:    configDaemon,
				ArgsUsage: "[<option>=(enable|disable) ...]",
			},
			{
				Name:   "status",
				Usage:  "Returns the daemon current status",
				Action: statusDaemon,
			},
		},
	}
}

func statusDaemon(ctx *cli.Context) {
	var (
		client *cnc.Client
		err    error
	)
	if host := ctx.GlobalString("host"); host == "" {
		client, err = cnc.NewDefaultClient()
	} else {
		client, err = cnc.NewClient(host, nil)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating cilium-client: %s\n", err)
		os.Exit(1)
	}

	if sr, err := client.GlobalStatus(); err != nil {
		fmt.Fprintf(os.Stderr, "Status: ERROR - Unable to reach out daemon: %s\n", err)
		os.Exit(1)
	} else {
		w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
		fmt.Fprintf(w, "KVStore:\t%s\n", sr.KVStore)
		fmt.Fprintf(w, "Docker:\t%s\n", sr.Docker)
		fmt.Fprintf(w, "Kubernetes:\t%s\n", sr.Kubernetes)
		fmt.Fprintf(w, "Cilium:\t%s\n", sr.Cilium)
		w.Flush()

		if sr.IPAMStatus != nil {
			fmt.Printf("V4 addresses reserved:\n")
			for _, ipv4 := range sr.IPAMStatus["4"] {
				fmt.Printf(" %s\n", ipv4)

			}
			fmt.Printf("V6 addresses reserved:\n")
			for _, ipv6 := range sr.IPAMStatus["6"] {
				fmt.Printf(" %s\n", ipv6)
			}
			w.Flush()
		}

		os.Exit(int(sr.Cilium.Code))
	}

}

func configDaemon(ctx *cli.Context) {
	var (
		client *cnc.Client
		err    error
	)

	first := ctx.Args().First()

	if first == "list" {
		for k, s := range daemon.DaemonOptionLibrary {
			fmt.Printf("%-24s %s\n", k, s.Description)
		}
		return
	}

	if host := ctx.GlobalString("host"); host == "" {
		client, err = cnc.NewDefaultClient()
	} else {
		client, err = cnc.NewClient(host, nil)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating cilium-client: %s\n", err)
		os.Exit(1)
	}

	res, err := client.Ping()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to reach daemon: %s\n", err)
		os.Exit(1)
	}

	if res == nil {
		fmt.Fprintf(os.Stderr, "Empty response from daemon\n")
		os.Exit(1)
	}

	opts := ctx.Args()

	if len(opts) == 0 {
		res.Opts.Dump()
		return
	}

	dOpts := make(types.OptionMap, len(opts))

	for k := range opts {
		name, value, err := types.ParseOption(opts[k], &daemon.DaemonOptionLibrary)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}

		dOpts[name] = value

		err = client.Update(dOpts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to update daemon: %s\n", err)
			os.Exit(1)
		}
	}
}

func initEnv(ctx *cli.Context) error {
	config.OptsMU.Lock()
	if ctx.GlobalBool("debug") {
		common.SetupLOG(log, "DEBUG")
		config.Opts.Set(types.OptionDebug, true)
	} else {
		common.SetupLOG(log, "INFO")
	}

	config.Opts.Set(types.OptionDropNotify, true)
	config.Opts.Set(types.OptionNAT46, false)
	config.Opts.Set(daemon.OptionPolicyTracing, enableTracing)
	config.Opts.Set(types.OptionConntrack, !disableConntrack)
	config.Opts.Set(types.OptionConntrackAccounting, !disableConntrack)
	config.Opts.Set(types.OptionPolicy, !disablePolicy)
	config.OptsMU.Unlock()

	config.ValidLabelPrefixesMU.Lock()
	if labelPrefixFile != "" {
		var err error
		config.ValidLabelPrefixes, err = types.ReadLabelPrefixCfgFrom(labelPrefixFile)
		if err != nil {
			log.Fatalf("Unable to read label prefix file: %s\n", err)
		}
	} else {
		config.ValidLabelPrefixes = types.DefaultLabelPrefixCfg()
	}
	config.ValidLabelPrefixesMU.Unlock()

	_, r, err := net.ParseCIDR(nat46prefix)
	if err != nil {
		log.Fatalf("Invalid NAT46 prefix %s: %s", nat46prefix, err)
	}

	config.NAT46Prefix = r

	nodeAddress, err := addressing.NewNodeAddress(v6Address, v4Prefix, config.Device)
	if err != nil {
		log.Fatalf("Unable to parse node address: %s", err)
	}

	config.NodeAddress = nodeAddress

	// Mount BPF Map directory if not already done
	args := []string{"-q", common.BPFMapRoot}
	_, err = exec.Command("mountpoint", args...).CombinedOutput()
	if err != nil {
		args = []string{"bpffs", common.BPFMapRoot, "-t", "bpf"}
		out, err := exec.Command("mount", args...).CombinedOutput()
		if err != nil {
			log.Fatalf("Command execution failed: %s\n%s", err, out)
		}
	}

	if config.IsK8sEnabled() && !strings.HasPrefix(config.K8sEndpoint, "http") {
		config.K8sEndpoint = "http://" + config.K8sEndpoint
	}

	if uiServerAddr != "" {
		if _, _, err := common.ParseHost(uiServerAddr); err != nil {
			log.Fatalf("Invalid UI server address and port address '%s': %s", uiServerAddr, err)
		}
		config.UIServerAddr = uiServerAddr
	}

	return nil
}

func run(cli *cli.Context) {
	if consulAddr != "" {
		consulDefaultAPI := consulAPI.DefaultConfig()
		consulSplitAddr := strings.Split(consulAddr, "://")
		if len(consulSplitAddr) == 2 {
			consulAddr = consulSplitAddr[1]
		} else if len(consulSplitAddr) == 1 {
			consulAddr = consulSplitAddr[0]
		}
		consulDefaultAPI.Address = consulAddr
		config.ConsulConfig = consulDefaultAPI
	}
	if len(etcdAddr.Value()) != 0 && config.EtcdCfgPath == "" {
		config.EtcdConfig = &etcdAPI.Config{}
		config.EtcdConfig.Endpoints = etcdAddr.Value()
	}

	d, err := daemon.NewDaemon(config)
	if err != nil {
		log.Fatalf("Error while creating daemon: %s", err)
		return
	}

	if err := d.PolicyInit(); err != nil {
		log.Fatalf("Unable to initialize policy: %s", err)
	}

	d.EnableConntrackGC()

	if enableLogstash {
		go d.EnableLogstash(logstashAddr, logstashProbeTimer)
	}

	d.EnableLearningTraffic()

	// Register event listener in docker endpoint
	if err := d.EnableDockerEventListener(); err != nil {
		log.Warningf("Error while enabling docker event watcher %s", err)
	}

	d.EnableKVStoreWatcher(30 * time.Second)

	if err := d.EnableK8sWatcher(5 * time.Minute); err != nil {
		log.Warningf("Error while enabling k8s watcher %s", err)
	}

	go d.EnableDockerSync(false)

	if config.IsUIEnabled() {
		uiServer, err := s.NewUIServer(config.UIServerAddr, d)
		if err != nil {
			log.Fatalf("Error while creating ui server: %s", err)
		}
		defer uiServer.Stop()
		go uiServer.Start()
	} else {
		log.Info("UI is disabled")
	}

	server, err := s.NewServer(socketPath, d)
	if err != nil {
		log.Fatalf("Error while creating daemon: %s", err)
	}
	defer server.Stop()
	server.Start()
}
