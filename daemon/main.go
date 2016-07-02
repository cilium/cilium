package daemon

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	common "github.com/noironetworks/cilium-net/common"
	cnc "github.com/noironetworks/cilium-net/common/client"
	"github.com/noironetworks/cilium-net/common/types"
	"github.com/noironetworks/cilium-net/daemon/daemon"
	s "github.com/noironetworks/cilium-net/daemon/server"

	"github.com/codegangsta/cli"
	consulAPI "github.com/hashicorp/consul/api"
	"github.com/op/go-logging"
)

var (
	config = daemon.NewConfig()

	// Arguments variables keep in alphabetical order
	consulAddr       string
	disableConntrack bool
	disablePolicy    bool
	enableTracing    bool
	labelPrefixFile  string
	nodeAddrStr      string
	socketPath       string
	uiServerAddr     string
	v4range          string

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
						Name:        "consul-agent, c",
						Value:       "127.0.0.1:8500",
						Usage:       "Consul agent address",
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
					cli.BoolFlag{
						Destination: &enableTracing,
						Name:        "enable-tracing",
						Usage:       "Enable tracing while determining policy",
					},
					cli.StringFlag{
						Destination: &config.IPv4Prefix,
						Name:        "ipv4-mapping",
						Value:       common.DefaultIPv4Prefix,
						Usage:       "IPv6 prefix to map IPv4 addresses to",
					},
					cli.StringFlag{
						Destination: &config.K8sEndpoint,
						Name:        "k",
						Value:       "http://[node-ipv6]:8080",
						Usage:       "Kubernetes endpoint to retrieve metadata information of new started containers",
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
						Value:       common.CiliumLibDir,
						Usage:       "Cilium library directory",
					},
					cli.StringFlag{
						Destination: &nodeAddrStr,
						Name:        "n",
						Value:       "",
						Usage:       "IPv6 address of node, must be in correct format",
					},
					cli.BoolTFlag{
						Destination: &config.RestoreState,
						Name:        "restore-state",
						Usage:       "Restore state from previous daemon",
					},
					cli.StringFlag{
						Destination: &config.RunDir,
						Name:        "R",
						Value:       "/var/run/cilium",
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
						Usage:       "IP address and port for UI server",
					},
					cli.StringFlag{
						Destination: &v4range,
						Name:        "ipv4-range",
						Value:       "",
						Usage:       "IPv6 prefix to map IPv4 addresses to",
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
		},
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

	for k, _ := range opts {
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

	if labelPrefixFile != "" {
		var err error
		config.ValidLabelPrefixes, err = types.ReadLabelPrefixCfgFrom(labelPrefixFile)
		if err != nil {
			log.Fatalf("Unable to read label prefix file: %s\n", err)
		}
	} else {
		config.ValidLabelPrefixes = types.DefaultLabelPrefixCfg()
	}

	if nodeAddrStr == "" {
		var err error
		nodeAddrStr, err = common.GenerateV6Prefix(config.Device)
		if err != nil {
			log.Fatalf("Unable to generate IPv6 prefix: %s\n", err)
		}

		log.Infof("Generated IPv6 prefix: %s\n", nodeAddrStr)
	}

	addr := net.ParseIP(nodeAddrStr)
	if addr == nil {
		log.Fatalf("Invalid node address \"%s\", please specifcy node address using -n", nodeAddrStr)
	}

	if !common.ValidNodeAddress(addr) {
		log.Fatalf("Invalid node address: %s", nodeAddrStr)
	}

	var err error
	config.NodeAddress, _, err = net.ParseCIDR(addr.String() + "/64")
	if err != nil {
		log.Fatalf("Invalid CIDR %s", addr.String())
	}

	if v4range == "" {
		v4range, err = common.GenerateV4Range(config.Device)
		if err != nil {
			log.Fatalf("Unable to generate IPv6 prefix: %s\n", err)
		}

		log.Infof("Generated IPv4 range: %s\n", v4range)
	}

	_, config.IPv4Range, err = net.ParseCIDR(v4range)
	if err != nil {
		log.Fatalf("Invalid IPv4 range %s: %s\n", v4range, err)
	}

	if ones, _ := config.IPv4Range.Mask.Size(); ones != common.DefaultIPv4Mask {
		log.Fatalf("IPv4 range %s must be of length %d\n", v4range, common.DefaultIPv4Mask)
	}

	if a := net.ParseIP(config.IPv4Prefix); a == nil || len(a) != net.IPv6len {
		log.Fatalf("Invalid IPv4 prefix %s", config.IPv4Prefix)
	}

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

	if config.K8sEndpoint == "http://[node-ipv6]:8080" {
		config.K8sEndpoint = fmt.Sprintf("http://[%s:ffff]:8080", strings.TrimSuffix(addr.String(), ":0"))
	}

	if uiServerAddr != "" {
		if _, tcpAddr, err := common.ParseHost(uiServerAddr); err != nil {
			log.Fatalf("Invalid UI server address and port address '%s': %s", uiServerAddr, err)
		} else {
			if !tcpAddr.IP.IsGlobalUnicast() {
				log.Fatalf("The UI IP address %q should be a reachable IP", tcpAddr.IP.String())
			}
		}
		config.UIServerAddr = uiServerAddr
	}

	return nil
}

func run(cli *cli.Context) {
	consulDefaultAPI := consulAPI.DefaultConfig()
	consulDefaultAPI.Address = consulAddr
	config.ConsulConfig = consulDefaultAPI

	d, err := daemon.NewDaemon(config)
	if err != nil {
		log.Fatalf("Error while creating daemon: %s", err)
		return
	}

	if err := d.PolicyInit(); err != nil {
		log.Fatalf("Unable to initialize policy: %s", err)
	}

	d.EnableConntrackGC()
	d.EnableLearningTraffic()

	// Register event listener in docker endpoint
	if err := d.EnableDockerEventListener(); err != nil {
		log.Warningf("Error while enabling docker event watcher %s", err)
	}
	d.EnableConsulWatcher(30 * time.Second)
	if err := d.EnableK8sWatcher(10 * time.Second); err != nil {
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
