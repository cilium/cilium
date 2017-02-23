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

package daemon

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/api/v1/server/restapi"
	common "github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/daemon/daemon"
	"github.com/cilium/cilium/pkg/bpf"
	clientPkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"

	etcdAPI "github.com/coreos/etcd/clientv3"
	loads "github.com/go-openapi/loads"
	consulAPI "github.com/hashicorp/consul/api"
	flags "github.com/jessevdk/go-flags"
	"github.com/op/go-logging"
	"github.com/urfave/cli"
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
	k8sLabels          cli.StringSlice
	labelPrefixFile    string
	logstashAddr       string
	logstashProbeTimer int
	socketPath         string
	v4Prefix           string
	v6Address          string
	nat46prefix        string
	bpfRoot            string

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
					cli.StringSliceFlag{
						Value: &k8sLabels,
						Name:  "k8s-prefix",
						Usage: "Key values that will be read from kubernetes. (Default: k8s-app, version)",
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
					cli.StringFlag{
						Destination: &bpfRoot,
						Name:        "bpf-root",
						EnvVar:      "BPF_ROOT",
						Usage:       "Path to mounted BPF filesystem",
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

var (
	client *clientPkg.Client
)

func initClient(ctx *cli.Context) {
	if cl, err := clientPkg.NewClient(ctx.GlobalString("host")); err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating client: %s\n", err)
		os.Exit(1)
	} else {
		client = cl
	}
}

func statusDaemon(ctx *cli.Context) {
	initClient(ctx)

	if resp, err := client.Daemon.GetHealthz(nil); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Unable to reach out daemon: %s\n", err)
		os.Exit(1)
	} else {
		sr := resp.Payload
		w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
		if sr.Kvstore != nil {
			fmt.Fprintf(w, "KVStore:\t%s\n", sr.Kvstore.State)
		}
		if sr.ContainerRuntime != nil {
			fmt.Fprintf(w, "ContainerRuntime:\t%s\n", sr.ContainerRuntime.State)
		}
		if sr.Kubernetes != nil {
			fmt.Fprintf(w, "Kubernetes:\t%s\n", sr.Kubernetes.State)
		}
		if sr.Cilium != nil {
			fmt.Fprintf(w, "Cilium:\t%s\n", sr.Cilium.State)
		}

		if sr.IPAM != nil {
			fmt.Printf("Allocated IPv4 addresses:\n")
			for _, ipv4 := range sr.IPAM.IPV4 {
				fmt.Printf(" %s\n", ipv4)

			}
			fmt.Printf("Allocated IPv6 addresses:\n")
			for _, ipv6 := range sr.IPAM.IPV6 {
				fmt.Printf(" %s\n", ipv6)
			}
		}

		w.Flush()

		if sr.Cilium != nil && sr.Cilium.State != models.StatusStateOk {
			os.Exit(1)
		} else {
			os.Exit(0)
		}
	}

}

func dumpConfig(Opts map[string]string) {
	opts := []string{}
	for k := range Opts {
		opts = append(opts, k)
	}
	sort.Strings(opts)

	for _, k := range opts {
		text := common.Green("Enabled")

		if Opts[k] == "" {
			text = common.Red("Disabled")
		}

		fmt.Printf("%-24s %s\n", k, text)
	}
}

func configDaemon(ctx *cli.Context) {
	first := ctx.Args().First()
	if first == "list" {
		for k, s := range daemon.DaemonOptionLibrary {
			fmt.Printf("%-24s %s\n", k, s.Description)
		}
		return
	}

	initClient(ctx)

	opts := ctx.Args()
	if len(opts) == 0 {
		resp, err := client.ConfigGet()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while retrieving configuration: %s", err)
			os.Exit(1)
		}

		dumpConfig(resp.Configuration.Immutable)
		dumpConfig(resp.Configuration.Mutable)
		return
	}

	dOpts := make(models.ConfigurationMap, len(opts))

	for k := range opts {
		name, value, err := option.ParseOption(opts[k], &daemon.DaemonOptionLibrary)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}

		if value {
			dOpts[name] = "Enabled"
		} else {
			dOpts[name] = "Disabled"
		}

		if err = client.ConfigPatch(dOpts); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to set daemon configuration: %s\n", err)
			os.Exit(1)
		}
	}
}

func initEnv(ctx *cli.Context) error {
	// The standard operation is to mount the BPF filesystem to the
	// standard location (/sys/fs/bpf). The user may chose to specify
	// the path to an already mounted filesystem instead. This is
	// useful if the daemon is being round inside a namespace and the
	// BPF filesystem is mapped into the slave namespace.
	if bpfRoot != "" {
		bpf.SetMapRoot(bpfRoot)
	} else if err := bpf.MountFS(); err != nil {
		log.Fatalf("Unable to mount BPF filesystem: %s\n", err)
	}

	config.OptsMU.Lock()
	if ctx.GlobalBool("debug") {
		common.SetupLOG(log, "DEBUG")
		config.Opts.Set(endpoint.OptionDebug, true)
	} else {
		common.SetupLOG(log, "INFO")
	}

	config.Opts.Set(endpoint.OptionDropNotify, true)
	config.Opts.Set(endpoint.OptionNAT46, true)
	config.Opts.Set(daemon.OptionPolicyTracing, enableTracing)
	config.Opts.Set(endpoint.OptionConntrack, !disableConntrack)
	config.Opts.Set(endpoint.OptionConntrackAccounting, !disableConntrack)
	config.Opts.Set(endpoint.OptionPolicy, !disablePolicy)
	config.OptsMU.Unlock()

	config.ValidLabelPrefixesMU.Lock()
	if labelPrefixFile != "" {
		var err error
		config.ValidLabelPrefixes, err = labels.ReadLabelPrefixCfgFrom(labelPrefixFile)
		if err != nil {
			log.Fatalf("Unable to read label prefix file: %s\n", err)
		}
	} else {
		config.ValidLabelPrefixes = labels.DefaultLabelPrefixCfg()
	}

	if len(k8sLabels) == 0 {
		config.ValidK8sLabelPrefixes = labels.DefaultK8sLabelPrefixCfg()
	} else {
		for _, prefix := range k8sLabels {
			config.ValidK8sLabelPrefixes.LabelPrefixes = append(
				config.ValidK8sLabelPrefixes.LabelPrefixes,
				&labels.LabelPrefix{Prefix: prefix, Source: common.K8sLabelSource},
			)
		}
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

	if config.IsK8sEnabled() && !strings.HasPrefix(config.K8sEndpoint, "http") {
		config.K8sEndpoint = "http://" + config.K8sEndpoint
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

	d.EnableMonitor()

	var wg sync.WaitGroup
	sinceLastSync := time.Now()
	d.SyncDocker(&wg)
	wg.Wait()

	// Register event listener in docker endpoint
	if err := d.EnableDockerEventListener(sinceLastSync); err != nil {
		log.Warningf("Error while enabling docker event watcher %s", err)
	}

	d.EnableKVStoreWatcher(30 * time.Second)

	if err := d.EnableK8sWatcher(5 * time.Minute); err != nil {
		log.Warningf("Error while enabling k8s watcher %s", err)
	}

	go d.EnableDockerSync()

	swaggerSpec, err := loads.Analyzed(server.SwaggerJSON, "")
	if err != nil {
		log.Fatal(err)
	}

	api := restapi.NewCiliumAPI(swaggerSpec)

	api.Logger = log.Infof

	// /healthz/
	api.DaemonGetHealthzHandler = daemon.NewGetHealthzHandler(d)

	// /config/
	api.DaemonGetConfigHandler = daemon.NewGetConfigHandler(d)
	api.DaemonPatchConfigHandler = daemon.NewPatchConfigHandler(d)

	// /endpoint/
	api.EndpointGetEndpointHandler = daemon.NewGetEndpointHandler(d)

	// /endpoint/{id}
	api.EndpointGetEndpointIDHandler = daemon.NewGetEndpointIDHandler(d)
	api.EndpointPutEndpointIDHandler = daemon.NewPutEndpointIDHandler(d)
	api.EndpointPatchEndpointIDHandler = daemon.NewPatchEndpointIDHandler(d)
	api.EndpointDeleteEndpointIDHandler = daemon.NewDeleteEndpointIDHandler(d)

	// /endpoint/{id}config/
	api.EndpointGetEndpointIDConfigHandler = daemon.NewGetEndpointIDConfigHandler(d)
	api.EndpointPatchEndpointIDConfigHandler = daemon.NewPatchEndpointIDConfigHandler(d)

	// /endpoint/{id}/labels/
	api.EndpointGetEndpointIDLabelsHandler = daemon.NewGetEndpointIDLabelsHandler(d)
	api.EndpointPutEndpointIDLabelsHandler = daemon.NewPutEndpointIDLabelsHandler(d)

	// /identity/
	api.PolicyGetIdentityHandler = daemon.NewGetIdentityHandler(d)
	api.PolicyGetIdentityIDHandler = daemon.NewGetIdentityIDHandler(d)

	// /policy/
	api.PolicyGetPolicyHandler = daemon.NewGetPolicyHandler(d)
	// /policy/{path}
	api.PolicyGetPolicyPathHandler = daemon.NewGetPolicyPathHandler(d)
	api.PolicyPutPolicyPathHandler = daemon.NewPutPolicyPathHandler(d)
	api.PolicyDeletePolicyPathHandler = daemon.NewDeletePolicyPathHandler(d)

	// /policy/resolve/
	api.PolicyGetPolicyResolveHandler = daemon.NewGetPolicyResolveHandler(d)

	// /service/{id}/
	api.ServiceGetServiceIDHandler = daemon.NewGetServiceIDHandler(d)
	api.ServiceDeleteServiceIDHandler = daemon.NewDeleteServiceIDHandler(d)
	api.ServicePutServiceIDHandler = daemon.NewPutServiceIDHandler(d)

	// /service/
	api.ServiceGetServiceHandler = daemon.NewGetServiceHandler(d)

	// /ipam/{ip}/
	api.IPAMPostIPAMHandler = daemon.NewPostIPAMHandler(d)
	api.IPAMPostIPAMIPHandler = daemon.NewPostIPAMIPHandler(d)
	api.IPAMDeleteIPAMIPHandler = daemon.NewDeleteIPAMIPHandler(d)

	server := server.NewServer(api)
	server.EnabledListeners = []string{"http", "unix"}
	server.SocketPath = flags.Filename(socketPath)
	defer server.Shutdown()

	server.ConfigureAPI()

	if err := server.Serve(); err != nil {
		log.Fatal(err)
	}
}
