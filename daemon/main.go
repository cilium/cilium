package daemon

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/noironetworks/cilium-net/bpf/lxcmap"
	common "github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"
	"github.com/noironetworks/cilium-net/daemon/daemon"
	s "github.com/noironetworks/cilium-net/daemon/server"

	"github.com/codegangsta/cli"
	consulAPI "github.com/hashicorp/consul/api"
	"github.com/op/go-logging"
	"github.com/vishvananda/netlink"
)

var (
	// Arguments variables keep in alphabetical order
	config          daemon.Config
	consulAddr      string
	device          string
	ipv4Prefix      string
	labelPrefixFile string
	nodeAddrStr     string
	runDir          string
	socketPath      string
	uiServerAddr    string
	v4range         string
	tunnel          string

	log = logging.MustGetLogger("cilium-net-daemon")

	// CliCommand is the command that will be used in cilium-net main program.
	CliCommand cli.Command
)

func init() {
	CliCommand = cli.Command{
		Name:   "daemon",
		Usage:  "Enables daemon mode",
		Before: initEnv,
		Action: run,
		// Keep Destination alphabetical order
		Flags: []cli.Flag{
			cli.StringFlag{
				Destination: &consulAddr,
				Name:        "consul-agent, c",
				Value:       "127.0.0.1:8500",
				Usage:       "Consul agent address",
			},
			cli.StringFlag{
				Destination: &device,
				Name:        "snoop-device, d",
				Value:       "undefined",
				Usage:       "Device to snoop on",
			},
			cli.BoolFlag{
				Destination: &config.DisableConntrack,
				Name:        "disable-conntrack",
				Usage:       "Disable connection tracking",
			},
			cli.BoolFlag{
				Destination: &config.DisablePolicy,
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
				Destination: &config.EnableTracing,
				Name:        "enable-tracing",
				Usage:       "Enable tracing while determining policy",
			},
			cli.StringFlag{
				Destination: &ipv4Prefix,
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
				Destination: &runDir,
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
				Destination: &tunnel,
				Name:        "t",
				Value:       "vxlan",
				Usage:       "Tunnel mode vxlan or geneve, vxlan is the default",
			},
		},
	}
}

func initBPF() error {
	var args []string

	if err := os.Chdir(runDir); err != nil {
		log.Fatalf("Could not change to runtime directory %s: \"%s\"",
			runDir, err)
	}

	f, err := os.Create("./globals/node_config.h")
	if err != nil {
		log.Warningf("Failed to create node configuration file: %s", err)
		return err

	}
	fw := bufio.NewWriter(f)

	hostIP := common.DupIP(config.NodeAddress)
	hostIP[14] = 0xff
	hostIP[15] = 0xff

	fmt.Fprintf(fw, ""+
		"/*\n"+
		" * Node-IP: %s\n"+
		" * Host-IP: %s\n"+
		" */\n\n",
		config.NodeAddress.String(), hostIP.String())

	fmt.Fprintf(fw, "#define NODE_ID %#x\n", common.NodeAddr2ID(config.NodeAddress))
	fw.WriteString(common.FmtDefineArray("ROUTER_IP", config.NodeAddress))

	SrcPrefix := net.ParseIP(ipv4Prefix)
	DstPrefix := net.ParseIP(ipv4Prefix)
	fw.WriteString(common.FmtDefineAddress("NAT46_SRC_PREFIX", SrcPrefix))
	fw.WriteString(common.FmtDefineAddress("NAT46_DST_PREFIX", DstPrefix))

	fw.WriteString(common.FmtDefineAddress("HOST_IP", hostIP))
	fmt.Fprintf(fw, "#define HOST_ID %d\n", types.GetID(types.ID_NAME_HOST))
	fmt.Fprintf(fw, "#define WORLD_ID %d\n", types.GetID(types.ID_NAME_WORLD))

	fmt.Fprintf(fw, "#define IPV4_RANGE %#x\n", binary.LittleEndian.Uint32(config.IPv4Range.IP))
	fmt.Fprintf(fw, "#define IPV4_MASK %#x\n", binary.LittleEndian.Uint32(config.IPv4Range.Mask))

	ipv4Gw := common.DupIP(config.IPv4Range.IP)
	ipv4Gw[2] = 0xff
	ipv4Gw[3] = 0xff
	fmt.Fprintf(fw, "#define IPV4_GW %#x\n", binary.LittleEndian.Uint32(ipv4Gw))

	fw.Flush()
	f.Close()

	if device != "undefined" {
		if _, err := netlink.LinkByName(device); err != nil {
			log.Warningf("Link %s does not exist: %s", device, err)
			return err
		}

		args = []string{config.LibDir, config.NodeAddress.String(), config.IPv4Range.IP.String(), "direct", device}
	} else {
		args = []string{config.LibDir, config.NodeAddress.String(), config.IPv4Range.IP.String(), tunnel}
	}

	out, err := exec.Command(config.LibDir+"/init.sh", args...).CombinedOutput()
	if err != nil {
		log.Warningf("Command execution %s/init.sh %s failed: %s",
			config.LibDir, strings.Join(args, " "), err)
		log.Warningf("Command output:\n%s", out)
		return err
	}

	config.LXCMap, err = lxcmap.OpenMap(common.BPFMap)
	if err != nil {
		log.Warningf("Could not create BPF map '%s': %s", common.BPFMap, err)
		return err
	}

	os.MkdirAll(common.CiliumUIPath, 0755)
	if err != nil {
		log.Warningf("Could not create UI directory '%s': %s", common.CiliumUIPath, err)
		return err
	}

	return nil
}

func initEnv(ctx *cli.Context) error {
	if ctx.GlobalBool("debug") {
		common.SetupLOG(log, "DEBUG")
	} else {
		common.SetupLOG(log, "INFO")
	}

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
		nodeAddrStr, err = common.GenerateV6Prefix(device)
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
		v4range, err = common.GenerateV4Range(device)
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

	if a := net.ParseIP(ipv4Prefix); a == nil || len(a) != net.IPv6len {
		log.Fatalf("Invalid IPv4 prefix %s", ipv4Prefix)
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

	return initBPF()
}

func run(cli *cli.Context) {
	consulDefaultAPI := consulAPI.DefaultConfig()
	consulDefaultAPI.Address = consulAddr
	config.ConsulConfig = consulDefaultAPI

	d, err := daemon.NewDaemon(&config)
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
