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
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/noironetworks/cilium-net/bpf/lxcmap"
	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/addressing"
	"github.com/noironetworks/cilium-net/common/ipam"
	"github.com/noironetworks/cilium-net/common/types"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	hb "github.com/containernetworking/cni/plugins/ipam/host-local/backend"
	dClient "github.com/docker/engine-api/client"
	consulAPI "github.com/hashicorp/consul/api"
	"github.com/op/go-logging"
	"github.com/vishvananda/netlink"
	k8sClientConfig "k8s.io/kubernetes/pkg/client/restclient"
	k8sClient "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/registry/service/ipallocator"
)

var (
	log = logging.MustGetLogger("cilium-net")
)

// Daemon is the cilium daemon that is in charge of perform all necessary plumbing,
// monitoring when a LXC starts.
type Daemon struct {
	ipamConf                  *ipam.IPAMConfig
	consul                    *consulAPI.Client
	containers                map[string]*types.Container
	containersMU              sync.RWMutex
	endpoints                 map[uint16]*types.Endpoint
	endpointsDocker           map[string]*types.Endpoint
	endpointsDockerEP         map[string]*types.Endpoint
	endpointsMU               sync.RWMutex
	endpointsLearning         map[uint16]types.LearningLabel
	endpointsLearningMU       sync.RWMutex
	endpointsLearningRegister chan types.LearningLabel
	dockerClient              *dClient.Client
	k8sClient                 *k8sClient.Client
	conf                      *Config
	policyTree                types.PolicyTree
	policyTreeMU              sync.RWMutex
	cacheIteration            int
	reservedConsumables       []*types.Consumable
	uiTopo                    types.UITopo
	uiListeners               map[*Conn]bool
	registerUIListener        chan *Conn
}

func createConsulClient(config *consulAPI.Config) (*consulAPI.Client, error) {
	var (
		c   *consulAPI.Client
		err error
	)
	if config != nil {
		c, err = consulAPI.NewClient(config)
	} else {
		c, err = consulAPI.NewClient(consulAPI.DefaultConfig())
	}
	if err != nil {
		return nil, err
	}
	maxRetries := 30
	i := 0
	for {
		leader, err := c.Status().Leader()
		if err != nil || leader == "" {
			log.Info("Waiting for consul client to be ready...")
			time.Sleep(2 * time.Second)
			i++
			if i > maxRetries {
				e := fmt.Errorf("Unable to contact consul")
				log.Error(e)
				return nil, e
			}
		} else {
			log.Info("Consul client ready")
			break
		}
	}
	return c, nil
}

func createDockerClient(endpoint string) (*dClient.Client, error) {
	defaultHeaders := map[string]string{"User-Agent": "cilium"}
	return dClient.NewClient(endpoint, "v1.21", nil, defaultHeaders)
}

func createK8sClient(endpoint string) (*k8sClient.Client, error) {
	config := k8sClientConfig.Config{Host: endpoint}
	k8sClientConfig.SetKubernetesDefaults(&config)
	return k8sClient.New(&config)
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

func (d *Daemon) compileBase() error {
	var args []string
	var mode string

	if err := d.writeNetdevHeader("./"); err != nil {
		log.Warningf("Unable to write netdev header: %s\n", err)
		return err
	}

	if d.conf.Device != "undefined" {
		if _, err := netlink.LinkByName(d.conf.Device); err != nil {
			log.Warningf("Link %s does not exist: %s", d.conf.Device, err)
			return err
		}

		if d.conf.LBMode {
			mode = "lb"
		} else {
			mode = "direct"
		}

		args = []string{d.conf.LibDir, d.conf.RunDir, d.conf.NodeAddress.String(), d.conf.NodeAddress.IPv4Address.String(), mode, d.conf.Device}
	} else {
		args = []string{d.conf.LibDir, d.conf.RunDir, d.conf.NodeAddress.String(), d.conf.NodeAddress.IPv4Address.String(), d.conf.Tunnel}
	}

	out, err := exec.Command(filepath.Join(d.conf.LibDir, "init.sh"), args...).CombinedOutput()
	if err != nil {
		log.Warningf("Command execution %s %s failed: %s",
			filepath.Join(d.conf.LibDir, "init.sh"),
			strings.Join(args, " "), err)
		log.Warningf("Command output:\n%s", out)
		return err
	}

	return nil
}

func (d *Daemon) init() error {
	globalsDir := filepath.Join(d.conf.RunDir, "globals")
	if err := os.MkdirAll(globalsDir, 0755); err != nil {
		log.Fatalf("Could not create runtime directory %s: %s", globalsDir, err)
	}

	if err := os.Chdir(d.conf.RunDir); err != nil {
		log.Fatalf("Could not change to runtime directory %s: \"%s\"",
			d.conf.RunDir, err)
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

	if d.conf.IPv4Enabled {
		fmt.Fprintf(fw, ""+
			" * Host-IPv4: %s\n"+
			" */\n\n"+
			"#define ENABLE_IPV4\n",
			d.conf.NodeAddress.IPv4Address.IP().String())
	} else {
		fw.WriteString(" */\n\n")
	}

	fmt.Fprintf(fw, "#define NODE_ID %#x\n", d.conf.NodeAddress.IPv6Address.NodeID())
	fw.WriteString(common.FmtDefineArray("ROUTER_IP", d.conf.NodeAddress.IPv6Address))

	ipv4GW := d.conf.NodeAddress.IPv4Address
	fmt.Fprintf(fw, "#define IPV4_GATEWAY %#x\n", binary.LittleEndian.Uint32(ipv4GW))

	ipv4Range := d.conf.NodeAddress.IPv4AllocRange()
	fmt.Fprintf(fw, "#define IPV4_RANGE %#x\n", binary.LittleEndian.Uint32(ipv4Range.IP))
	fmt.Fprintf(fw, "#define IPV4_MASK %#x\n", binary.LittleEndian.Uint32(ipv4Range.Mask))

	ipv4ClusterRange := d.conf.NodeAddress.IPv4ClusterRange()
	fmt.Fprintf(fw, "#define IPV4_CLUSTER_RANGE %#x\n", binary.LittleEndian.Uint32(ipv4ClusterRange.IP))
	fmt.Fprintf(fw, "#define IPV4_CLUSTER_MASK %#x\n", binary.LittleEndian.Uint32(ipv4ClusterRange.Mask))

	if nat46Range := d.conf.NAT46Prefix; nat46Range != nil {
		fw.WriteString(common.FmtDefineAddress("NAT46_SRC_PREFIX", nat46Range.IP))
		fw.WriteString(common.FmtDefineAddress("NAT46_DST_PREFIX", nat46Range.IP))
	}

	fw.WriteString(common.FmtDefineAddress("HOST_IP", hostIP))
	fmt.Fprintf(fw, "#define HOST_ID %d\n", types.GetID(types.ID_NAME_HOST))
	fmt.Fprintf(fw, "#define WORLD_ID %d\n", types.GetID(types.ID_NAME_WORLD))

	fw.Flush()
	f.Close()

	if !d.conf.DryMode {
		d.conf.OptsMU.RLock()
		if err := d.compileBase(); err != nil {
			d.conf.OptsMU.RUnlock()
			return err
		}
		d.conf.OptsMU.RUnlock()

		d.conf.LXCMap, err = lxcmap.OpenMap(common.BPFMap)
		if err != nil {
			log.Warningf("Could not create BPF map '%s': %s", common.BPFMap, err)
			return err
		}
	}

	return nil
}

// NewDaemon creates and returns a new Daemon with the parameters set in c.
func NewDaemon(c *Config) (*Daemon, error) {
	if c == nil {
		return nil, fmt.Errorf("Configuration is nil")
	}

	ipamSubnets := net.IPNet{
		IP:   c.NodeAddress.IPv6Address.IP(),
		Mask: addressing.StateIPv6Mask,
	}

	ipamConf := &ipam.IPAMConfig{
		IPAMConfig: hb.IPAMConfig{
			Name:    string(ipam.CNIIPAMType),
			Subnet:  cniTypes.IPNet(ipamSubnets),
			Gateway: c.NodeAddress.IPv6Address.IP(),
			Routes: []cniTypes.Route{
				// IPv6
				cniTypes.Route{
					Dst: c.NodeAddress.IPv6Route,
				},
				cniTypes.Route{
					Dst: addressing.IPv6DefaultRoute,
					GW:  c.NodeAddress.IPv6Address.IP(),
				},
			},
		},
		IPv6Allocator: ipallocator.NewCIDRRange(c.NodeAddress.IPv6AllocRange()),
	}

	if c.IPv4Enabled {
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

	var consul *consulAPI.Client

	if c.ConsulConfig != nil {
		c, err := createConsulClient(c.ConsulConfig)
		if err != nil {
			return nil, err
		}
		consul = c
	}

	dockerClient, err := createDockerClient(c.DockerEndpoint)
	if err != nil {
		return nil, err
	}

	k8sClient, err := createK8sClient(c.K8sEndpoint)
	if err != nil {
		return nil, err
	}

	rootNode := types.PolicyTree{
		Root: types.NewPolicyNode(common.GlobalLabelPrefix, nil),
	}

	rootNode.Root.Path()

	d := Daemon{
		conf:                      c,
		ipamConf:                  ipamConf,
		consul:                    consul,
		dockerClient:              dockerClient,
		k8sClient:                 k8sClient,
		containers:                make(map[string]*types.Container),
		endpoints:                 make(map[uint16]*types.Endpoint),
		endpointsDocker:           make(map[string]*types.Endpoint),
		endpointsDockerEP:         make(map[string]*types.Endpoint),
		endpointsLearning:         make(map[uint16]types.LearningLabel),
		endpointsLearningRegister: make(chan types.LearningLabel, 1),
		cacheIteration:            1,
		reservedConsumables:       make([]*types.Consumable, 0),
		policyTree:                rootNode,
		uiTopo:                    types.NewUITopo(),
		uiListeners:               make(map[*Conn]bool),
		registerUIListener:        make(chan *Conn, 1),
	}

	if err := d.init(); err != nil {
		log.Fatalf("Error while initializing daemon: %s\n", err)
	}

	if d.conf.IsUIEnabled() {
		d.ListenBuildUIEvents()
	}

	if c.RestoreState {
		if err := d.SyncState(common.CiliumPath, true); err != nil {
			log.Warningf("Error while recovering endpoints: %s\n", err)
		}
	}

	return &d, nil
}

func changedOption(key string, value bool, data interface{}) {
}

func (d *Daemon) Update(opts types.OptionMap) error {
	d.conf.OptsMU.Lock()
	defer d.conf.OptsMU.Unlock()

	if err := d.conf.Opts.Validate(opts); err != nil {
		return err
	}

	changes := d.conf.Opts.Apply(opts, changedOption, d)
	if changes > 0 {
		if err := d.compileBase(); err != nil {
			log.Warningf("Unable to recompile base programs: %s\n", err)
		}
	}

	return nil
}
