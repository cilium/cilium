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

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/ipam"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/daemon/defaults"
	"github.com/cilium/cilium/daemon/options"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/events"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy"

	log "github.com/Sirupsen/logrus"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	hb "github.com/containernetworking/cni/plugins/ipam/host-local/backend/allocator"
	dClient "github.com/docker/engine-api/client"
	"github.com/go-openapi/runtime/middleware"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/registry/core/service/ipallocator"
)

const (
	// ExecTimeout is the execution timeout to use in init.sh executions
	ExecTimeout = time.Duration(30 * time.Second)
)

// Daemon is the cilium daemon that is in charge of perform all necessary plumbing,
// monitoring when a LXC starts.
type Daemon struct {
	buildEndpointChan chan *endpoint.Request
	conf              *Config
	consumableCache   *policy.ConsumableCache
	dockerClient      *dClient.Client
	events            chan events.Event
	ipamConf          *ipam.IPAMConfig
	k8sClient         *kubernetes.Clientset
	kvClient          kvstore.KVClient
	l7Proxy           *proxy.Proxy
	loadBalancer      *types.LoadBalancer
	loopbackIPv4      net.IP
	policy            *policy.Repository

	containersMU sync.RWMutex
	containers   map[string]*container.Container

	endpointsMU  sync.RWMutex
	endpoints    map[uint16]*endpoint.Endpoint
	endpointsAux map[string]*endpoint.Endpoint

	ignoredMutex      sync.RWMutex
	ignoredContainers map[string]int

	maxCachedLabelIDMU sync.RWMutex
	maxCachedLabelID   policy.NumericIdentity

	uniqueIDMU sync.Mutex
	uniqueID   map[uint64]bool
}

func (d *Daemon) GetProxy() *proxy.Proxy {
	return d.l7Proxy
}

func (d *Daemon) WriteEndpoint(e *endpoint.Endpoint) error {
	if err := d.conf.LXCMap.WriteEndpoint(e); err != nil {
		return fmt.Errorf("Unable to update eBPF map: %s", err)
	}

	return nil
}

// QueueEndpointBuild puts the given request in the endpoints queue for
// processing. The given request will receive 'true' in the MyTurn channel
// whenever it's its turn or false if the request was denied/canceled.
func (d *Daemon) QueueEndpointBuild(req *endpoint.Request) {
	go func(req *endpoint.Request) {
		d.uniqueIDMU.Lock()
		// We are skipping new requests, but only if the endpoint has not
		// started its build process, since the endpoint is already in queue.
		if isBuilding, exists := d.uniqueID[req.ID]; !isBuilding && exists {
			req.MyTurn <- false
		} else {
			// We mark the request "not building" state and send it to
			// the building queue.
			d.uniqueID[req.ID] = false
			d.buildEndpointChan <- req
		}
		d.uniqueIDMU.Unlock()
	}(req)
}

// RemoveFromEndpointQueue removes the endpoint from the queue.
func (d *Daemon) RemoveFromEndpointQueue(epID uint64) {
	d.uniqueIDMU.Lock()
	delete(d.uniqueID, epID)
	d.uniqueIDMU.Unlock()
}

// StartEndpointBuilders creates `nRoutines` go routines that listen on the
// `d.buildEndpointChan` for new endpoints.
func (d *Daemon) StartEndpointBuilders(nRoutines int) {
	log.Debugf("Creating %d worker threads", nRoutines)
	for w := 0; w < nRoutines; w++ {
		go func() {
			for e := range d.buildEndpointChan {
				d.uniqueIDMU.Lock()
				if _, ok := d.uniqueID[e.ID]; !ok {
					// If the request is not present in the uniqueID,
					// it means the request was deleted from the queue
					// so we deny the request's turn.
					e.MyTurn <- false
					d.uniqueIDMU.Unlock()
					continue
				}
				// Set the endpoint to "building" state
				d.uniqueID[e.ID] = true
				e.MyTurn <- true
				d.uniqueIDMU.Unlock()
				// Wait for the endpoint to build
				<-e.Done
				d.uniqueIDMU.Lock()
				// In a case where the same endpoint enters the
				// building queue, while it was still being build,
				// it will be marked as `false`/"not building",
				// thus, we only delete the endpoint from the
				// queue only if it is marked as isBuilding.
				if isBuilding := d.uniqueID[e.ID]; isBuilding {
					delete(d.uniqueID, e.ID)
				}
				d.uniqueIDMU.Unlock()
			}
		}()
	}
}

// GetStateDir returns the path to the state directory
func (d *Daemon) GetStateDir() string {
	return d.conf.StateDir
}

func (d *Daemon) GetBpfDir() string {
	return d.conf.BpfDir
}

// GetPolicyRepository returns the policy repository of the daemon
func (d *Daemon) GetPolicyRepository() *policy.Repository {
	return d.policy
}

func (d *Daemon) GetConsumableCache() *policy.ConsumableCache {
	return d.consumableCache
}

func (d *Daemon) TracingEnabled() bool {
	return d.conf.Opts.IsEnabled(options.PolicyTracing)
}

func (d *Daemon) DryModeEnabled() bool {
	return d.conf.DryMode
}

// AlwaysAllowLocalhost returns true if the daemon has the option set that
// localhost can always reach local endpoints
func (d *Daemon) AlwaysAllowLocalhost() bool {
	return d.conf.alwaysAllowLocalhost
}

func (d *Daemon) PolicyEnabled() bool {
	return d.conf.Opts.IsEnabled(endpoint.OptionPolicy)
}

func (d *Daemon) PolicyEnforcement() string {
	return d.conf.EnablePolicy
}

// DebugEnabled returns whether if debug mode is enabled.
func (d *Daemon) DebugEnabled() bool {
	return d.conf.Opts.IsEnabled(endpoint.OptionDebug)
}

func createDockerClient(endpoint string) (*dClient.Client, error) {
	defaultHeaders := map[string]string{"User-Agent": "cilium"}
	return dClient.NewClient(endpoint, "v1.21", nil, defaultHeaders)
}

func (d *Daemon) writeNetdevHeader(dir string) error {
	headerPath := filepath.Join(dir, common.NetdevHeaderFileName)
	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %s", headerPath, err)

	}
	defer f.Close()

	fw := bufio.NewWriter(f)
	fw.WriteString(d.conf.Opts.GetFmtList())

	return fw.Flush()
}

func (d *Daemon) setHostAddresses() error {
	l, err := netlink.LinkByName(d.conf.LBInterface)
	if err != nil {
		return fmt.Errorf("unable to get network device %s: %s", d.conf.Device, err)
	}

	getAddr := func(netLinkFamily int) (net.IP, error) {
		addrs, err := netlink.AddrList(l, netLinkFamily)
		if err != nil {
			return nil, fmt.Errorf("error while getting %s's addresses: %s", d.conf.Device, err)
		}
		for _, possibleAddr := range addrs {
			if netlink.Scope(possibleAddr.Scope) == netlink.SCOPE_UNIVERSE {
				return possibleAddr.IP, nil
			}
		}
		return nil, nil
	}

	if !d.conf.IPv4Disabled {
		hostV4Addr, err := getAddr(netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		if hostV4Addr != nil {
			d.conf.HostV4Addr = hostV4Addr
			log.Infof("Using IPv4 host address: %s", d.conf.HostV4Addr)
		}
	}
	hostV6Addr, err := getAddr(netlink.FAMILY_V6)
	if err != nil {
		return err
	}
	if hostV6Addr != nil {
		d.conf.HostV6Addr = hostV6Addr
		log.Infof("Using IPv6 host address: %s", d.conf.HostV6Addr)
	}
	return nil
}

func (d *Daemon) compileBase() error {
	var args []string
	var mode string

	if err := d.writeNetdevHeader("./"); err != nil {
		log.Warningf("Unable to write netdev header: %s\n", err)
		return err
	}

	if d.conf.Device != "undefined" {
		_, err := netlink.LinkByName(d.conf.Device)
		if err != nil {
			log.Warningf("Link %s does not exist: %s", d.conf.Device, err)
			return err
		}

		if d.conf.IsLBEnabled() {
			if d.conf.Device != d.conf.LBInterface {
				//FIXME: allow different interfaces
				return fmt.Errorf("Unable to have an interface for LB mode different than snooping interface")
			}
			if err := d.setHostAddresses(); err != nil {
				return err
			}
			mode = "lb"
		} else {
			mode = "direct"
		}

		args = []string{d.conf.BpfDir, d.conf.StateDir, d.conf.NodeAddress.String(), d.conf.NodeAddress.IPv4Address.String(), mode, d.conf.Device}
	} else {
		args = []string{d.conf.BpfDir, d.conf.StateDir, d.conf.NodeAddress.String(), d.conf.NodeAddress.IPv4Address.String(), d.conf.Tunnel}
	}

	prog := filepath.Join(d.conf.BpfDir, "init.sh")
	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, prog, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		log.Errorf("Command execution failed: Timeout for %s %s", prog, args)
		return fmt.Errorf("Command execution failed: Timeout for %s %s", prog, args)
	}
	if err != nil {
		log.Warningf("Command execution %s %s failed: %s", prog,
			strings.Join(args, " "), err)
		log.Warningf("Command output:\n%s", out)
		return err
	}

	log.Info("Setting sysctl net.core.bpf_jit_enable=1")
	log.Info("Setting sysctl net.ipv4.conf.all.rp_filter=0")
	log.Info("Setting sysctl net.ipv6.conf.all.disable_ipv6=0")

	return nil
}

// useK8sNodeCIDR sets the ipv4-range value from the cluster-node-cidr defined in the,
// kube-apiserver.
func (d *Daemon) useK8sNodeCIDR(nodeName string) error {
	if d.conf.IPv4Disabled {
		return nil
	}
	k8sNode, err := d.k8sClient.Nodes().Get(nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if k8sNode.Spec.PodCIDR == "" {
		log.Warningf("K8s node %s spec did not provide a CIDR", nodeName)
		return nil
	}
	ip, _, err := net.ParseCIDR(k8sNode.Spec.PodCIDR)
	if err != nil {
		return err
	}
	ciliumIPv4, err := addressing.NewCiliumIPv4(ip.String())
	if err != nil {
		return err
	}
	ipv6NodeAddress := d.conf.NodeAddress.IPv6Address.NodeIP().String()
	nodeAddr, err := addressing.NewNodeAddress(ipv6NodeAddress, ciliumIPv4.NodeIP().String(), "")
	if err != nil {
		return err
	}
	log.Infof("Retrieved %s for node %s. Using it for ipv4-range", k8sNode.Spec.PodCIDR, nodeName)
	d.conf.NodeAddress = nodeAddr
	return nil
}

func (d *Daemon) init() error {
	globalsDir := filepath.Join(d.conf.StateDir, "globals")
	if err := os.MkdirAll(globalsDir, defaults.RuntimePathRights); err != nil {
		log.Fatalf("Could not create runtime directory %s: %s", globalsDir, err)
	}

	if err := os.Chdir(d.conf.StateDir); err != nil {
		log.Fatalf("Could not change to runtime directory %s: \"%s\"",
			d.conf.StateDir, err)
	}

	f, err := os.Create("./globals/node_config.h")
	if err != nil {
		log.Warningf("Failed to create node configuration file: %s", err)
		return err

	}
	fw := bufio.NewWriter(f)

	hostIP := d.conf.NodeAddress.IPv6Address.HostIP()

	fmt.Fprintf(fw, ""+
		"/*\n"+
		" * Node-IPv6: %s\n"+
		" * Host-IPv6: %s\n",
		d.conf.NodeAddress.IPv6Address.IP().String(),
		hostIP.String())

	if d.conf.IPv4Disabled {
		fw.WriteString(" */\n\n")
	} else {
		fmt.Fprintf(fw, ""+
			" * Host-IPv4: %s\n"+
			" */\n\n"+
			"#define ENABLE_IPV4\n",
			d.conf.NodeAddress.IPv4Address.IP().String())
	}

	fmt.Fprintf(fw, "#define NODE_ID %#x\n", d.conf.NodeAddress.IPv6Address.NodeID())
	fw.WriteString(common.FmtDefineComma("ROUTER_IP", d.conf.NodeAddress.IPv6Address))

	ipv4GW := d.conf.NodeAddress.IPv4Address
	fmt.Fprintf(fw, "#define IPV4_GATEWAY %#x\n", binary.LittleEndian.Uint32(ipv4GW))

	if !d.conf.IPv4Disabled {
		fmt.Fprintf(fw, "#define IPV4_LOOPBACK %#x\n", binary.LittleEndian.Uint32(d.loopbackIPv4))
	}

	ipv4Range := d.conf.NodeAddress.IPv4AllocRange()
	fmt.Fprintf(fw, "#define IPV4_RANGE %#x\n", binary.LittleEndian.Uint32(ipv4Range.IP))
	fmt.Fprintf(fw, "#define IPV4_MASK %#x\n", binary.LittleEndian.Uint32(ipv4Range.Mask))

	ipv4ClusterRange := d.conf.NodeAddress.IPv4ClusterRange()
	fmt.Fprintf(fw, "#define IPV4_CLUSTER_RANGE %#x\n", binary.LittleEndian.Uint32(ipv4ClusterRange.IP))
	fmt.Fprintf(fw, "#define IPV4_CLUSTER_MASK %#x\n", binary.LittleEndian.Uint32(ipv4ClusterRange.Mask))

	if nat46Range := d.conf.NAT46Prefix; nat46Range != nil {
		fw.WriteString(common.FmtDefineAddress("NAT46_PREFIX", nat46Range.IP))
	}

	fw.WriteString(common.FmtDefineComma("HOST_IP", hostIP))
	fmt.Fprintf(fw, "#define HOST_ID %d\n", policy.GetReservedID(labels.IDNameHost))
	fmt.Fprintf(fw, "#define WORLD_ID %d\n", policy.GetReservedID(labels.IDNameWorld))
	fmt.Fprintf(fw, "#define LB_RR_MAX_SEQ %d\n", lbmap.MaxSeq)

	fw.Flush()
	f.Close()

	if !d.DryModeEnabled() {
		if err := d.compileBase(); err != nil {
			return err
		}
		d.conf.LXCMap, err = lxcmap.OpenMap()
		if err != nil {
			log.Warningf("Could not create BPF endpoint map: %s", err)
			return err
		}

		if _, err := lbmap.Service6Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RevNat6Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RRSeq6Map.OpenOrCreate(); err != nil {
			return err
		}
		if !d.conf.IPv4Disabled {
			if _, err := lbmap.Service4Map.OpenOrCreate(); err != nil {
				return err
			}
			if _, err := lbmap.RevNat4Map.OpenOrCreate(); err != nil {
				return err
			}
			if _, err := lbmap.RRSeq4Map.OpenOrCreate(); err != nil {
				return err
			}
		}
		// Clean all lb entries
		if !d.conf.RestoreState {
			// FIXME Remove all loadbalancer entries
		}
	}

	return nil
}

func (c *Config) createIPAMConf() (*ipam.IPAMConfig, error) {

	ipamSubnets := net.IPNet{
		IP:   c.NodeAddress.IPv6Address.IP(),
		Mask: addressing.StateIPv6Mask,
	}

	ipamConf := &ipam.IPAMConfig{
		IPAMConfig: hb.IPAMConfig{
			Name:    "cilium-local-IPAM",
			Subnet:  cniTypes.IPNet(ipamSubnets),
			Gateway: c.NodeAddress.IPv6Address.IP(),
			Routes: []cniTypes.Route{
				// IPv6
				{
					Dst: c.NodeAddress.IPv6Route,
				},
				{
					Dst: addressing.IPv6DefaultRoute,
					GW:  c.NodeAddress.IPv6Address.IP(),
				},
			},
		},
		IPv6Allocator: ipallocator.NewCIDRRange(c.NodeAddress.IPv6AllocRange()),
	}

	if !c.IPv4Disabled {
		ipamConf.IPv4Allocator = ipallocator.NewCIDRRange(c.NodeAddress.IPv4AllocRange())
		ipamConf.IPAMConfig.Routes = append(ipamConf.IPAMConfig.Routes,
			// IPv4
			cniTypes.Route{
				Dst: c.NodeAddress.IPv4Route,
			},
			cniTypes.Route{
				Dst: addressing.IPv4DefaultRoute,
				GW:  c.NodeAddress.IPv4Address.IP(),
			})
		// Reserve the IPv4 router IP in the IPv4 allocation range to ensure
		// that we do not hand out the router IP to a container.
		err := ipamConf.IPv4Allocator.Allocate(c.NodeAddress.IPv4Address.IP())
		if err != nil {
			return nil, fmt.Errorf("Unable to reserve IPv4 router address %s: %s",
				c.NodeAddress.IPv4Address.String(), err)
		}

	}

	return ipamConf, nil
}

// NewDaemon creates and returns a new Daemon with the parameters set in c.
func NewDaemon(c *Config) (*Daemon, error) {
	if c == nil {
		return nil, fmt.Errorf("Configuration is nil")
	}

	var kvClient kvstore.KVClient

	// Create new key-value store client structures based on provided kvstore type.
	switch c.KVStore {
	case kvstore.Consul:
		if c.ConsulConfig != nil {
			log.Infof("Using consul as key-value store")
			c, err := kvstore.NewConsulClient(c.ConsulConfig)
			if err != nil {
				return nil, err
			}
			kvClient = c
		} else {
			return nil, fmt.Errorf("invalid configuration for consul provided; please specify the address to a consul instance with the consul.address option")
		}
	case kvstore.Etcd:
		if c.EtcdCfgPath != "" || c.EtcdConfig != nil {
			log.Infof("Using etcd as key-value store")
			c, err := kvstore.NewEtcdClient(c.EtcdConfig, c.EtcdCfgPath)
			if err != nil {
				return nil, err
			}
			kvClient = c
		} else {
			return nil, fmt.Errorf("invalid configuration for etcd provided; please specify an etcd configuration path with etcd.config or an etcd agent address with etcd.address")
		}
	case kvstore.Local:
		log.Infof("Using local storage as key-value store")
		kvClient = kvstore.NewLocalClient()
	}

	dockerClient, err := createDockerClient(c.DockerEndpoint)
	if err != nil {
		return nil, err
	}

	lb := types.NewLoadBalancer()

	d := Daemon{
		conf:              c,
		kvClient:          kvClient,
		dockerClient:      dockerClient,
		containers:        make(map[string]*container.Container),
		endpoints:         make(map[uint16]*endpoint.Endpoint),
		endpointsAux:      make(map[string]*endpoint.Endpoint),
		events:            make(chan events.Event, 512),
		loadBalancer:      lb,
		consumableCache:   policy.NewConsumableCache(),
		policy:            policy.NewPolicyRepository(),
		ignoredContainers: make(map[string]int),
		buildEndpointChan: make(chan *endpoint.Request, common.EndpointsPerHost),
		uniqueID:          map[uint64]bool{},
	}

	// Create the same amount of worker threads as there are CPUs
	d.StartEndpointBuilders(runtime.NumCPU())

	d.listenForCiliumEvents()

	if c.IsK8sEnabled() {
		d.k8sClient, err = k8s.CreateClient(c.K8sEndpoint, c.K8sCfgPath)
		if err != nil {
			return nil, err
		}

		if nodeName := os.Getenv(k8s.EnvNodeNameSpec); nodeName != "" {
			// Try to retrieve node's cidr from k8s's configuration
			if err := d.useK8sNodeCIDR(nodeName); err != nil {
				return nil, err
			}
		}

		// Kubernetes demands that the localhost can always reach local
		// pods. Therefore unless the AllowLocalhost policy is set to a
		// specific mode, always allow localhost to reach local
		// endpoints.
		if d.conf.AllowLocalhost == AllowLocalhostAuto {
			log.Infof("k8s mode: Allowing localhost to reach local endpoints")
			config.alwaysAllowLocalhost = true
		}
	}

	// Set up ipam conf after init() because we might be running d.conf.KVStoreIPv4Registration
	if d.ipamConf, err = d.conf.createIPAMConf(); err != nil {
		return nil, err
	}

	log.Infof("Cluster IPv6 prefix: %s", d.conf.NodeAddress.IPv6ClusterRange())
	log.Infof("Cluster IPv4 prefix: %s", d.conf.NodeAddress.IPv4ClusterRange())
	log.Infof("IPv6 allocation prefix: %s", d.conf.NodeAddress.IPv6AllocRange())
	log.Infof("IPv4 allocation prefix: %s", d.conf.NodeAddress.IPv4AllocRange())

	if !d.conf.IPv4Disabled {
		// Allocate IPv4 service loopback IP
		loopbackIPv4, err := d.ipamConf.IPv4Allocator.AllocateNext()
		if err != nil {
			return nil, fmt.Errorf("Unable to reserve IPv4 loopback address: %s", err)
		}
		d.loopbackIPv4 = loopbackIPv4
	}

	if err = d.init(); err != nil {
		log.Errorf("Error while initializing daemon: %s\n", err)
		return nil, err
	}

	// FIXME: Make configurable
	d.l7Proxy = proxy.NewProxy(10000, 20000)

	if c.RestoreState {
		if err := d.SyncState(d.conf.StateDir, true); err != nil {
			log.Warningf("Error while recovering endpoints: %s\n", err)
		}
		if err := d.SyncLBMap(); err != nil {
			log.Warningf("Error while recovering endpoints: %s\n", err)
		}
	} else {
		// We need to read all docker containers so we know we won't
		// going to allocate the same IP addresses and we will ignore
		// these containers from reading.
		d.IgnoreRunningContainers()
	}

	d.collectStaleMapGarbage()

	return &d, nil
}

func (d *Daemon) collectStaleMapGarbage() {
	d.endpointsMU.RLock()
	defer d.endpointsMU.RUnlock()

	walker := func(path string, _ os.FileInfo, _ error) error {
		return d.staleMapWalker(path)
	}

	if err := filepath.Walk(bpf.MapPrefixPath(), walker); err != nil {
		log.Warningf("Error while scanning for stale maps: %s", err)
	}
}

func (d *Daemon) removeStaleMap(path string) {
	if err := os.RemoveAll(path); err != nil {
		log.Warningf("Error while deleting stale map file %s: %s", path, err)
	} else {
		log.Infof("Removed stale bpf map %s", path)
	}
}

// call with d.endpointsMU.RLocked
func (d *Daemon) checkStaleMap(path string, filename string, id string) {
	if tmp, err := strconv.ParseUint(id, 0, 16); err == nil {
		if _, ok := d.endpoints[uint16(tmp)]; !ok {
			d.removeStaleMap(path)
		}
	}
}

// call with d.endpointsMU.RLocked
func (d *Daemon) checkStaleGlobalMap(path string, filename string) {
	var globalCTinUse = false

	for k := range d.endpoints {
		e := d.endpoints[k]
		if e.Consumable != nil &&
			e.Opts.IsDisabled(endpoint.OptionConntrackLocal) {
			globalCTinUse = true
			break
		}
	}

	if !globalCTinUse &&
		(filename == ctmap.MapName6Global ||
			filename == ctmap.MapName4Global) {
		d.removeStaleMap(path)
	}
}

// call with d.endpointsMU.RLocked
func (d *Daemon) staleMapWalker(path string) error {
	filename := filepath.Base(path)

	mapPrefix := []string{
		policymap.MapName,
		ctmap.MapName6,
		ctmap.MapName4,
	}

	d.checkStaleGlobalMap(path, filename)

	for _, m := range mapPrefix {
		if strings.HasPrefix(filename, m) {
			if id := strings.TrimPrefix(filename, m); id != filename {
				d.checkStaleMap(path, filename, id)
			}
		}
	}

	return nil
}

func changedOption(key string, value bool, data interface{}) {
}

type patchConfig struct {
	daemon *Daemon
}

func NewPatchConfigHandler(d *Daemon) PatchConfigHandler {
	return &patchConfig{daemon: d}
}

func (h *patchConfig) Handle(params PatchConfigParams) middleware.Responder {
	log.Debugf("PATCH /config request: %+v", params)

	d := h.daemon

	if err := d.conf.Opts.Validate(params.Configuration); err != nil {
		return apierror.Error(PatchConfigBadRequestCode, err)
	}

	changes := d.conf.Opts.Apply(params.Configuration, changedOption, d)
	log.Debugf("Applied %d changes", changes)
	if changes > 0 {
		_, ok := params.Configuration[endpoint.OptionPolicy]
		if ok {
			if config.Opts.IsEnabled(endpoint.OptionPolicy) && config.EnablePolicy != endpoint.AlwaysEnforce {
				config.EnablePolicy = endpoint.AlwaysEnforce
			} else if !config.Opts.IsEnabled(endpoint.OptionPolicy) && config.EnablePolicy != endpoint.NeverEnforce {
				config.EnablePolicy = endpoint.NeverEnforce
			}
		}
		if err := d.compileBase(); err != nil {
			msg := fmt.Errorf("Unable to recompile base programs: %s\n", err)
			log.Warningf("%s", msg)
			return apierror.Error(PatchConfigFailureCode, msg)
		}
	}

	return NewPatchConfigOK()
}

func (d *Daemon) getNodeAddressing() *models.NodeAddressing {
	addr := d.conf.NodeAddress

	return &models.NodeAddressing{
		IPV6: &models.NodeAddressingElement{
			Enabled:    true,
			IP:         addr.IPv6Address.String(),
			AllocRange: addr.IPv6AllocRange().String(),
		},
		IPV4: &models.NodeAddressingElement{
			Enabled:    !d.conf.IPv4Disabled,
			IP:         addr.IPv4Address.String(),
			AllocRange: addr.IPv4AllocRange().String(),
		},
	}
}

type getConfig struct {
	daemon *Daemon
}

func NewGetConfigHandler(d *Daemon) GetConfigHandler {
	return &getConfig{daemon: d}
}

func (h *getConfig) Handle(params GetConfigParams) middleware.Responder {
	log.Debugf("GET /config request: %+v", params)

	d := h.daemon

	cfg := &models.DaemonConfigurationResponse{
		Addressing:    d.getNodeAddressing(),
		Configuration: d.conf.Opts.GetModel(),
	}

	return NewGetConfigOK().WithPayload(cfg)
}

func (d *Daemon) IgnoredContainer(id string) bool {
	d.ignoredMutex.RLock()
	_, ok := d.ignoredContainers[id]
	d.ignoredMutex.RUnlock()

	return ok
}

func (d *Daemon) StartIgnoringContainer(id string) {
	d.ignoredMutex.Lock()
	d.ignoredContainers[id]++
	d.ignoredMutex.Unlock()
}

func (d *Daemon) StopIgnoringContainer(id string) {
	d.ignoredMutex.Lock()
	delete(d.ignoredContainers, id)
	d.ignoredMutex.Unlock()
}
