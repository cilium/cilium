package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/noironetworks/cilium-net/bpf/lxcmap"
	"github.com/noironetworks/cilium-net/cilium-net-daemon/daemon"
	s "github.com/noironetworks/cilium-net/cilium-net-daemon/server"
	common "github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	consulAPI "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/hashicorp/consul/api"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/op/go-logging"
)

const (
	// RFC3339Mili is the RFC3339 with miliseconds for the default timestamp format
	// log files.
	RFC3339Mili = "2006-01-02T15:04:05.999Z07:00"
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
	logLevel           string
	nodeAddrStr        string
	runDir             string
	socketPath         string
	v4range            string
	tunnel             string

	ipv4Range          *net.IPNet
	log                = logging.MustGetLogger("cilium-net")
	lxcMap             *lxcmap.LXCMap
	nodeAddr           net.IP
	validLabelPrefixes *types.LabelPrefixCfg
)

func setupLOG(logLevel, hostname string) {

	fileFormat := logging.MustStringFormatter(
		`%{time:` + RFC3339Mili + `} ` + hostname +
			` %{level:.4s} %{id:03x} %{shortfunc} > %{message}`,
	)

	level, err := logging.LogLevel(logLevel)
	if err != nil {
		log.Fatal(err)
	}

	backend := logging.NewLogBackend(os.Stderr, "", 0)
	oBF := logging.NewBackendFormatter(backend, fileFormat)

	backendLeveled := logging.SetBackend(oBF)
	backendLeveled.SetLevel(level, "")
	log.SetBackend(backendLeveled)
}

func initBPF() {
	var args []string

	if err := os.Chdir(runDir); err != nil {
		log.Fatalf("Could not change to runtime directory %s: \"%s\"",
			runDir, err)
		return
	}

	f, err := os.Create("./globals/node_config.h")
	if err != nil {
		// TODO: warning doesn't stop the daemon
		log.Warningf("Failed to create node configuration file: %s", err)
		return

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

	if logLevel == "debug" {
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
		// TODO: warning doesn't stop the daemon
		log.Warningf("Command execution failed: %s", err)
		log.Warningf("Command output:\n%s", out)
		return
	}

	lxcMap, err = lxcmap.OpenMap(common.BPFMap)
	if err != nil {
		// TODO: warning doesn't stop the daemon
		log.Warningf("Could not create BPF map '%s': %s", common.BPFMap, err)
		return
	}
}

func init() {
	// Keep in alphabetical order
	flag.StringVar(&consulAddr, "c", "127.0.0.1:8500", "Consul agent address")
	flag.StringVar(&device, "d", "undefined", "Device to snoop on")
	flag.BoolVar(&disablePolicy, "disable-policy", false, "Disable policy enforcement")
	flag.StringVar(&dockerEndpoint, "e", "unix:///var/run/docker.sock", "Register a listener for docker events on the given endpoint")
	flag.BoolVar(&enableTracing, "enable-tracing", false, "Enable tracing while determing policy")
	flag.StringVar(&hostname, "hostname", "", "Overwrites hostname's value that will be used for log messages")
	flag.StringVar(&ipv4Prefix, "ipv4-mapping", common.DefaultIPv4Prefix, "IPv6 prefix to map IPv4 addresses to")
	flag.StringVar(&kubernetesEndpoint, "k", "http://127.0.0.1:8080", "Kubernetes endpoint to retrieve metadata information of new started containers")
	flag.StringVar(&labelPrefixFile, "p", "", "File with valid label prefixes")
	flag.StringVar(&libDir, "D", "/usr/lib/cilium", "Cilium library directory")
	flag.StringVar(&logLevel, "l", "info", "Set log level, valid options are (debug|info|warning|error|fatal|panic)")
	flag.StringVar(&nodeAddrStr, "n", "", "IPv6 address of node, must be in correct format")
	flag.StringVar(&runDir, "R", "/var/run/cilium", "Runtime data directory")
	flag.StringVar(&socketPath, "s", common.CiliumSock, "Sets the socket path to listen for connections")
	flag.StringVar(&v4range, "ipv4-range", "", "IPv6 prefix to map IPv4 addresses to")
	flag.StringVar(&tunnel, "t", "vxlan", "tunnel mode vxlan or geneve, vxlan is the default")
	flag.Parse()

	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	setupLOG(logLevel, hostname)

	if labelPrefixFile != "" {
		var err error
		validLabelPrefixes, err = types.ReadLabelPrefixCfgFrom(labelPrefixFile)
		if err != nil {
			log.Fatalf("Unable to read label prefix file: %s\n", err)
			return
		}
	} else {
		validLabelPrefixes = types.DefaultLabelPrefixCfg()
	}

	if nodeAddrStr == "" {
		var err error
		nodeAddrStr, err = common.GenerateV6Prefix()
		if err != nil {
			log.Fatalf("Unable to generate IPv6 prefix: %s\n", err)
			return
		}

		log.Infof("Generated IPv6 prefix: %s\n", nodeAddrStr)
	}

	addr := net.ParseIP(nodeAddrStr)
	if addr == nil {
		log.Fatalf("Invalid node address \"%s\", please specifcy node address using -n", nodeAddrStr)
		return
	}

	if !common.ValidNodeAddress(addr) {
		log.Fatalf("Invalid node address: %s", nodeAddrStr)
	}

	var err error
	nodeAddr, _, err = net.ParseCIDR(addr.String() + "/64")
	if err != nil {
		log.Fatalf("Invalid CIDR %s", addr.String())
		return
	}

	if v4range == "" {
		v4range, err = common.GenerateV4Range()
		if err != nil {
			log.Fatalf("Unable to generate IPv6 prefix: %s\n", err)
			return
		}

		log.Infof("Generated IPv4 range: %s\n", v4range)
	}

	_, ipv4Range, err = net.ParseCIDR(v4range)
	if err != nil {
		log.Fatalf("Invalid IPv4 range %s: %s\n", v4range, err)
		return
	}

	if ones, _ := ipv4Range.Mask.Size(); ones != common.DefaultIPv4Mask {
		log.Fatalf("IPv4 range %s must be of length %d\n", v4range, common.DefaultIPv4Mask)
		return
	}

	if a := net.ParseIP(ipv4Prefix); a == nil || len(a) != net.IPv6len {
		log.Fatalf("Invalid IPv4 prefix %s", ipv4Prefix)
		return
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
		return
	}

	initBPF()
}

func main() {
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
