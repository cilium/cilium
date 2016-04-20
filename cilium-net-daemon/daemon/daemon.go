package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/noironetworks/cilium-net/bpf/lxcmap"
	"github.com/noironetworks/cilium-net/common"
	ciliumTypes "github.com/noironetworks/cilium-net/common/types"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/appc/cni/pkg/types"
	hb "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/appc/cni/plugins/ipam/host-local/backend"
	dClient "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/docker/engine-api/client"
	dTypes "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/docker/engine-api/types"
	dTypesEvents "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/docker/engine-api/types/events"
	consulAPI "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/hashicorp/consul/api"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/op/go-logging"
	k8sAPI "github.com/noironetworks/cilium-net/Godeps/_workspace/src/k8s.io/kubernetes/pkg/api"
	k8sClientConfig "github.com/noironetworks/cilium-net/Godeps/_workspace/src/k8s.io/kubernetes/pkg/client/restclient"
	k8sClient "github.com/noironetworks/cilium-net/Godeps/_workspace/src/k8s.io/kubernetes/pkg/client/unversioned"
	k8sDockerLbls "github.com/noironetworks/cilium-net/Godeps/_workspace/src/k8s.io/kubernetes/pkg/kubelet/dockertools"
)

const (
	ipamType = "cilium-host-local"
)

var (
	log = logging.MustGetLogger("cilium-net")
)

// Daemon is the cilium daemon that is in charge of perform all necessary plumbing,
// monitoring when a LXC starts.
type Daemon struct {
	libDir               string
	lxcMap               *lxcmap.LXCMap
	ipamConf             hb.IPAMConfig
	consul               *consulAPI.Client
	endpoints            map[string]*ciliumTypes.Endpoint
	endpointsMU          sync.Mutex
	validLabelPrefixes   *ciliumTypes.LabelPrefixCfg
	validLabelPrefixesMU sync.Mutex
	dockerClient         *dClient.Client
	k8sClient            *k8sClient.Client
	ipv4Range            *net.IPNet
	enableTracing        bool
	disablePolicy        bool
}

func createConsulClient(config *consulAPI.Config) (*consulAPI.Client, error) {
	if config != nil {
		return consulAPI.NewClient(config)
	}
	return consulAPI.NewClient(consulAPI.DefaultConfig())
}

func createDockerClient(endpoint string) (*dClient.Client, error) {
	defaultHeaders := map[string]string{"User-Agent": "engine-api-cli-1.0"}
	return dClient.NewClient(endpoint, "v1.21", nil, defaultHeaders)
}

func createK8sClient(endpoint string) (*k8sClient.Client, error) {
	config := k8sClientConfig.Config{Host: endpoint}
	k8sClientConfig.SetKubernetesDefaults(&config)
	return k8sClient.New(&config)
}

// NewDaemon creates and returns a new Daemon with the parameters set in c.
func NewDaemon(c *Config) (*Daemon, error) {
	if c == nil {
		return nil, fmt.Errorf("Configuration is nil")
	}
	nodeSubNet := net.IPNet{IP: c.NodeAddress, Mask: common.ContainerIPv6Mask}
	nodeRoute := net.IPNet{IP: c.NodeAddress, Mask: common.ContainerIPv6Mask}

	ipamConf := hb.IPAMConfig{
		Type:    ipamType,
		Subnet:  types.IPNet(nodeSubNet),
		Gateway: c.NodeAddress,
		Routes: []types.Route{
			types.Route{
				Dst: nodeRoute,
			},
			types.Route{
				Dst: net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
				GW:  c.NodeAddress,
			},
		},
	}

	consul, err := createConsulClient(c.ConsulConfig)
	if err != nil {
		return nil, err
	}

	dockerClient, err := createDockerClient(c.DockerEndpoint)
	if err != nil {
		return nil, err
	}

	k8sClient, err := createK8sClient(c.K8sEndpoint)
	if err != nil {
		return nil, err
	}

	return &Daemon{
		libDir:             c.LibDir,
		lxcMap:             c.LXCMap,
		ipamConf:           ipamConf,
		consul:             consul,
		dockerClient:       dockerClient,
		k8sClient:          k8sClient,
		endpoints:          make(map[string]*ciliumTypes.Endpoint),
		validLabelPrefixes: c.ValidLabelPrefixes,
		ipv4Range:          c.IPv4Range,
		enableTracing:      c.EnableTracing,
		disablePolicy:      c.DisablePolicy,
	}, nil
}

// ActivateConsulWatcher watches for consul changes in the common.LastFreeIDKeyPath key.
// Triggers policy updates every time the value of that key is changed.
func (d *Daemon) ActivateConsulWatcher(seconds time.Duration) {
	go func() {
		var (
			k   *consulAPI.KVPair
			q   *consulAPI.QueryMeta
			qo  consulAPI.QueryOptions
			err error
		)
		for {
			k, q, err = d.consul.KV().Get(common.LastFreeIDKeyPath, nil)
			if err != nil {
				log.Errorf("Unable to retreive last free Index: %s", err)
			}
			if k != nil {
				break
			} else {
				log.Info("Unable to retreive last free Index, please start some containers with labels.")
			}
			time.Sleep(seconds)
		}

		for {
			k, q, err = d.consul.KV().Get(common.LastFreeIDKeyPath, &qo)
			if err != nil {
				log.Errorf("Unable to retreive last free Index: %s", err)
			}
			if k == nil || q == nil {
				log.Warning("Unable to retreive last free Index, please start some containers with labels.")
				time.Sleep(time.Duration(5 * time.Second))
				continue
			}
			qo.WaitIndex = q.LastIndex
			go func() {
				d.TriggerPolicyUpdates([]int{-1})
			}()
		}
	}()
}

// ActivateEventListener watches for docker events. Performs the plumbing for the
// containers started or dead.
func (d *Daemon) ActivateEventListener() error {
	eo := dTypes.EventsOptions{Since: strconv.FormatInt(time.Now().Unix(), 10)}
	r, err := d.dockerClient.Events(eo)
	if err != nil {
		return err
	}
	log.Debugf("Listening for docker events")
	go d.listenForEvents(r)
	return nil
}

func (d *Daemon) listenForEvents(reader io.ReadCloser) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		var e dTypesEvents.Message
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			log.Errorf("Error while unmarshalling event: %+v", e)
		}
		log.Debugf("Processing an event %+v", e)
		go d.processEvent(e)
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error while reading events: %+v", err)
	}
}

func (d *Daemon) processEvent(m dTypesEvents.Message) {
	if m.Type == "container" {
		switch m.Status {
		case "start":
			d.createContainer(m)
		case "die":
			d.deleteContainer(m)
		}
	}
}

func getCiliumEndpointID(cont dTypes.ContainerJSON, gwIP net.IP) string {
	for _, contNetwork := range cont.NetworkSettings.Networks {
		ipv6gw := net.ParseIP(contNetwork.IPv6Gateway)
		if ipv6gw.Equal(gwIP) {
			ip := net.ParseIP(contNetwork.GlobalIPv6Address)
			id := common.EndpointAddr2ID(ip)
			return strconv.FormatUint(uint64(id), 10)
		}
	}
	return ""
}

func (d *Daemon) fetchK8sLabels(dockerLbls map[string]string) (map[string]string, error) {
	ns := k8sDockerLbls.GetPodNamespace(dockerLbls)
	if ns == "" {
		ns = "default"
	}
	podName := k8sDockerLbls.GetPodName(dockerLbls)
	if podName == "" {
		return nil, nil
	}
	result := &k8sAPI.Pod{}
	log.Debug("Connecting to kubernetes to retrieve labels for pod %s ns %s", podName, ns)
	if err := d.k8sClient.Get().Namespace(ns).Resource("pods").Name(podName).Do().Into(result); err != nil {
		return nil, err
	}
	//log.Debug("Retrieved %+v", result)
	return result.GetLabels(), nil
}

func (d *Daemon) getFilteredLabels(allLabels map[string]string) ciliumTypes.Labels {
	var ciliumLabels, k8sLabels ciliumTypes.Labels
	if podName := k8sDockerLbls.GetPodName(allLabels); podName != "" {
		k8sNormalLabels, err := d.fetchK8sLabels(allLabels)
		if err != nil {
			log.Warningf("Error while getting kubernetes labels: %s", err)
		} else if k8sNormalLabels != nil {
			k8sLabels = ciliumTypes.Map2Labels(k8sNormalLabels, common.K8sLabelSource)
		}
	}

	ciliumLabels = ciliumTypes.Map2Labels(allLabels, common.CiliumLabelSource)

	ciliumLabels.MergeLabels(k8sLabels)

	d.validLabelPrefixesMU.Lock()
	defer d.validLabelPrefixesMU.Unlock()
	return d.validLabelPrefixes.FilterLabels(ciliumLabels)
}

func (d *Daemon) createContainer(m dTypesEvents.Message) {
	dockerID := m.Actor.ID
	log.Debugf("Processing container %s", dockerID)
	allLabels := m.Actor.Attributes
	cont, err := d.dockerClient.ContainerInspect(dockerID)
	if err != nil {
		log.Errorf("Error while inspecting container '%s': %s", dockerID, err)
		return
	}

	ciliumLabels := d.getFilteredLabels(allLabels)

	secCtxlabels, isNew, err := d.PutLabels(ciliumLabels)
	if err != nil {
		log.Errorf("Error while getting labels ID: %s", err)
		return
	}
	defer func() {
		if err != nil {
			log.Infof("Deleting label ID %d because of failure.", secCtxlabels.ID)
			d.DeleteLabelsByUUID(secCtxlabels.ID)
		}
	}()

	ciliumID := getCiliumEndpointID(cont, d.ipamConf.Gateway)

	try := 1
	maxTries := 5
	var ep *ciliumTypes.Endpoint
	for try < maxTries {
		if ep = d.setEndpointSecLabel(ciliumID, dockerID, secCtxlabels); ep != nil {
			break
		}
		log.Warningf("Something went wrong, the endpoint for docker ID '%s' was not locally found. Attempt... %d", dockerID, try)
		time.Sleep(time.Duration(try) * time.Second)
		try++
	}
	if try >= maxTries {
		err = fmt.Errorf("It was impossible to store the SecLabel %d for docker ID '%s'", secCtxlabels.ID, dockerID)
		log.Error(err)
		return
	}
	if err = d.createBPF(*ep); err != nil {
		err = fmt.Errorf("Unable to create & attach BPF programs for container %s", ep.ID)
		log.Error(err)
		return
	}

	// Perform the policy map updates after programs have been created
	if isNew {
		d.TriggerPolicyUpdates([]int{secCtxlabels.ID})
	}

	log.Infof("Added SecLabel %d to container %s", secCtxlabels.ID, dockerID)
}

func (d *Daemon) deleteContainer(m dTypesEvents.Message) {
	dockerID := m.Actor.ID
	log.Debugf("Processing container %s", dockerID)
	allLabels := m.Actor.Attributes

	ciliumLabels := d.getFilteredLabels(allLabels)

	sha256sum, err := ciliumLabels.SHA256Sum()
	if err != nil {
		log.Errorf("Error while creating SHA256Sum for labels %+v: %s", ciliumLabels, err)
	}

	if err := d.DeleteLabelsBySHA256(sha256sum); err != nil {
		log.Errorf("Error while deleting labels (SHA256SUM:%s) %+v: %s", sha256sum, ciliumLabels, err)
	}
}
