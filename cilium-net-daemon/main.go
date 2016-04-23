package daemon

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/noironetworks/cilium-net/bpf/lxcmap"
	"github.com/noironetworks/cilium-net/cilium-net-daemon/daemon"
	s "github.com/noironetworks/cilium-net/cilium-net-daemon/server"
	common "github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/codegangsta/cli"
	consulAPI "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/hashicorp/consul/api"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/op/go-logging"
)

var (
	// Arguments variables keep in alphabetical order
	consulAddr         string
	device             string
	disablePolicy      bool
	dockerEndpoint     string
	enableTracing      bool
	hostname           string
	ipv4Prefix         string
	kubernetesEndpoint string
	labelPrefixFile    string
	libDir             string
	nodeAddrStr        string
	runDir             string
	socketPath         string
	v4range            string
	tunnel             string

	ipv4Range          *net.IPNet
	log                = logging.MustGetLogger("cilium-net-daemon")
	lxcMap             *lxcmap.LXCMap
	nodeAddr           net.IP
	validLabelPrefixes *types.LabelPrefixCfg

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
				Destination: &disablePolicy,
				Name:        "disable-policy",
				Usage:       "Disable policy enforcement",
			},
			cli.StringFlag{
				Destination: &dockerEndpoint,
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
				Destination: &hostname,
				Name:        "hostname",
				Value:       "",
				Usage:       "Overwrites hostname's value that will be used for log messages",
			},
			cli.StringFlag{
				Destination: &ipv4Prefix,
				Name:        "ipv4-mapping",
				Value:       common.DefaultIPv4Prefix,
				Usage:       "IPv6 prefix to map IPv4 addresses to",
			},
			cli.StringFlag{
				Destination: &kubernetesEndpoint,
				Name:        "k",
				Value:       "http://127.0.0.1:8080",
				Usage:       "Kubernetes endpoint to retrieve metadata information of new started containers",
			},
			cli.StringFlag{
				Destination: &labelPrefixFile,
				Name:        "p",
				Value:       "",
				Usage:       "File with valid label prefixes",
			},
			cli.StringFlag{
				Destination: &libDir,
				Name:        "D",
				Value:       "/usr/lib/cilium",
				Usage:       "Cilium library directory",
			},
			cli.StringFlag{
				Destination: &nodeAddrStr,
				Name:        "n",
				Value:       "",
				Usage:       "IPv6 address of node, must be in correct format",
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

	// TODO Change f to bufio.Writer
	f, err := os.Create("./globals/node_config.h")
	if err != nil {
		log.Warningf("Failed to create node configuration file: %s", err)
		return err

	}

	hostIP := common.DupIP(nodeAddr)
	hostIP[14] = 0xff
	hostIP[15] = 0xff

	fmt.Fprintf(f, ""+
		"/*\n"+
		" * Node-IP: %s\n"+
		" * Host-IP: %s\n"+
		" */\n\n",
		nodeAddr.String(), hostIP.String())

	if common.DebugEnabled {
		f.WriteString("#define DEBUG\n")
	}

	if disablePolicy {
		f.WriteString("#define DISABLE_POLICY_ENFORCEMENT\n")
	}

	fmt.Fprintf(f, "#define NODE_ID %#x\n", common.NodeAddr2ID(nodeAddr))
	f.WriteString(common.FmtDefineArray("ROUTER_IP", nodeAddr))

	SrcPrefix := net.ParseIP(ipv4Prefix)
	DstPrefix := net.ParseIP(ipv4Prefix)
	f.WriteString(common.FmtDefineAddress("NAT46_SRC_PREFIX", SrcPrefix))
	f.WriteString(common.FmtDefineAddress("NAT46_DST_PREFIX", DstPrefix))

	f.WriteString(common.FmtDefineAddress("HOST_IP", hostIP))
	fmt.Fprintf(f, "#define HOST_ID %d\n", types.GetID(types.ID_NAME_HOST))
	fmt.Fprintf(f, "#define WORLD_ID %d\n", types.GetID(types.ID_NAME_WORLD))

	fmt.Fprintf(f, "#define IPV4_RANGE %#x\n", binary.LittleEndian.Uint32(ipv4Range.IP))
	fmt.Fprintf(f, "#define IPV4_MASK %#x\n", binary.LittleEndian.Uint32(ipv4Range.Mask))

	ipv4Gw := common.DupIP(ipv4Range.IP)
	ipv4Gw[2] = 0xff
	ipv4Gw[3] = 0xff
	fmt.Fprintf(f, "#define IPV4_GW %#x\n", binary.LittleEndian.Uint32(ipv4Gw))

	f.Close()

	if device != "undefined" {
		args = []string{libDir, nodeAddr.String(), ipv4Range.IP.String(), "direct", device}
	} else {
		args = []string{libDir, nodeAddr.String(), ipv4Range.IP.String(), tunnel}
	}

	out, err := exec.Command(libDir+"/init.sh", args...).CombinedOutput()
	if err != nil {
		log.Warningf("Command execution %s/init.sh %s failed: %s",
			libDir, strings.Join(args, " "), err)
		log.Warningf("Command output:\n%s", out)
		return err
	}

	lxcMap, err = lxcmap.OpenMap(common.BPFMap)
	if err != nil {
		log.Warningf("Could not create BPF map '%s': %s", common.BPFMap, err)
		return err
	}
	return nil
}

func initEnv(ctx *cli.Context) error {
	if ctx.GlobalBool("debug") {
		common.SetupLOG(log, "DEBUG", hostname)
	} else {
		common.SetupLOG(log, "INFO", hostname)
	}

	if labelPrefixFile != "" {
		var err error
		validLabelPrefixes, err = types.ReadLabelPrefixCfgFrom(labelPrefixFile)
		if err != nil {
			log.Fatalf("Unable to read label prefix file: %s\n", err)
		}
	} else {
		validLabelPrefixes = types.DefaultLabelPrefixCfg()
	}

	if nodeAddrStr == "" {
		var err error
		nodeAddrStr, err = common.GenerateV6Prefix()
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
	nodeAddr, _, err = net.ParseCIDR(addr.String() + "/64")
	if err != nil {
		log.Fatalf("Invalid CIDR %s", addr.String())
	}

	if v4range == "" {
		v4range, err = common.GenerateV4Range()
		if err != nil {
			log.Fatalf("Unable to generate IPv6 prefix: %s\n", err)
		}

		log.Infof("Generated IPv4 range: %s\n", v4range)
	}

	_, ipv4Range, err = net.ParseCIDR(v4range)
	if err != nil {
		log.Fatalf("Invalid IPv4 range %s: %s\n", v4range, err)
	}

	if ones, _ := ipv4Range.Mask.Size(); ones != common.DefaultIPv4Mask {
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

	if err := daemon.PolicyInit(); err != nil {
		log.Fatalf("Unable to initialize policy: %s", err)
	}

	return initBPF()
}

func run(cli *cli.Context) {
	consulDefaultAPI := consulAPI.DefaultConfig()
	consulDefaultAPI.Address = consulAddr
	daemonConf := daemon.Config{
		LibDir:             libDir,
		LXCMap:             lxcMap,
		NodeAddress:        nodeAddr,
		IPv4Range:          ipv4Range,
		ConsulConfig:       consulDefaultAPI,
		DockerEndpoint:     dockerEndpoint,
		K8sEndpoint:        kubernetesEndpoint,
		EnableTracing:      enableTracing,
		ValidLabelPrefixes: validLabelPrefixes,
		DisablePolicy:      disablePolicy,
	}

	d, err := daemon.NewDaemon(&daemonConf)
	if err != nil {
		log.Fatalf("Error while creating daemon: %s", err)
		return
	}

	// Register event listener in docker endpoint
	d.ActivateEventListener()
	d.ActivateConsulWatcher(time.Duration(5 * time.Second))

	server, err := s.NewServer(socketPath, d)
	if err != nil {
		log.Fatalf("Error while creating daemon: %s", err)
	}
	defer server.Stop()
	server.Start()
}
