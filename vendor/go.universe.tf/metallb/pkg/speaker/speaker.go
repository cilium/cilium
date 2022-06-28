package speaker

import (
	"fmt"
	"net"

	"go.universe.tf/metallb/pkg/bgp"
	"go.universe.tf/metallb/pkg/config"
	"go.universe.tf/metallb/pkg/k8s"
	"go.universe.tf/metallb/pkg/k8s/types"
	"go.universe.tf/metallb/pkg/layer2"

	gokitlog "github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/api/core/v1"
)

func NewController(cfg ControllerConfig) (*Controller, error) {
	protocols := map[config.Proto]Protocol{
		config.BGP: &BGPController{
			Logger: cfg.Logger,
			MyNode: cfg.MyNode,
			SvcAds: make(map[string][]*bgp.Advertisement),
		},
	}

	if !cfg.DisableLayer2 {
		a, err := layer2.New(cfg.Logger)
		if err != nil {
			return nil, fmt.Errorf("making layer2 announcer: %s", err)
		}
		protocols[config.Layer2] = &Layer2Controller{
			Announcer: a,
			MyNode:    cfg.MyNode,
			SList:     cfg.SList,
		}
	}

	ret := &Controller{
		myNode:    cfg.MyNode,
		Protocols: protocols,
		announced: map[string]config.Proto{},
		svcIP:     map[string]net.IP{},
	}

	return ret, nil
}

type Controller struct {
	myNode string

	config *config.Config
	Client service

	Protocols map[config.Proto]Protocol
	announced map[string]config.Proto // service name -> protocol advertising it
	svcIP     map[string]net.IP       // service name -> assigned IP
}

type ControllerConfig struct {
	MyNode string
	Logger gokitlog.Logger
	SList  SpeakerList

	// For testing only, and will be removed in a future release.
	// See: https://github.com/metallb/metallb/issues/152.
	DisableLayer2 bool
}

// Service represents an object containing the minimal representation of a
// v1.Service object needed for announcements.
type Service struct {
	Type          string
	TrafficPolicy string
	Ingress       []v1.LoadBalancerIngress
}

func (c *Controller) SetBalancer(l gokitlog.Logger, name string, svc *v1.Service, eps k8s.EpsOrSlices) types.SyncState {
	s := c.SetService(l, name, &Service{
		Type:          string(svc.Spec.Type),
		TrafficPolicy: string(svc.Spec.ExternalTrafficPolicy),
		Ingress:       svc.Status.LoadBalancer.Ingress,
	}, toEndpoints(eps))
	if s == types.SyncStateSuccess {
		c.Client.Infof(svc, "nodeAssigned", "announcing from node %q", c.myNode)
	}
	return s
}

func (c *Controller) SetService(l gokitlog.Logger, name string, svc *Service, eps *Endpoints) types.SyncState {
	if svc == nil {
		return c.deleteBalancer(l, name, "serviceDeleted")
	}

	if svc.Type != "LoadBalancer" {
		return c.deleteBalancer(l, name, "notLoadBalancer")
	}

	l.Log("event", "startUpdate", "msg", "start of service update")
	defer l.Log("event", "endUpdate", "msg", "end of service update")

	if c.config == nil {
		l.Log("event", "noConfig", "msg", "not processing, still waiting for config")
		return types.SyncStateSuccess
	}

	if len(svc.Ingress) != 1 {
		return c.deleteBalancer(l, name, "noIPAllocated")
	}

	lbIP := net.ParseIP(svc.Ingress[0].IP)
	if lbIP == nil {
		l.Log("op", "setBalancer", "error", fmt.Sprintf("invalid LoadBalancer IP %q", svc.Ingress[0].IP), "msg", "invalid IP allocated by controller")
		return c.deleteBalancer(l, name, "invalidIP")
	}

	l = gokitlog.With(l, "ip", lbIP)

	poolName := poolFor(c.config.Pools, lbIP)
	if poolName == "" {
		l.Log("op", "setBalancer", "error", "assigned IP not allowed by config", "msg", "IP allocated by controller not allowed by config")
		return c.deleteBalancer(l, name, "ipNotAllowed")
	}

	l = gokitlog.With(l, "pool", poolName)
	pool := c.config.Pools[poolName]
	if pool == nil {
		l.Log("bug", "true", "msg", "internal error: allocated IP has no matching address pool")
		return c.deleteBalancer(l, name, "internalError")
	}

	if proto, ok := c.announced[name]; ok && proto != pool.Protocol {
		if st := c.deleteBalancer(l, name, "protocolChanged"); st == types.SyncStateError {
			return st
		}
	}

	if svcIP, ok := c.svcIP[name]; ok && !lbIP.Equal(svcIP) {
		if st := c.deleteBalancer(l, name, "loadBalancerIPChanged"); st == types.SyncStateError {
			return st
		}
	}

	l = gokitlog.With(l, "protocol", pool.Protocol)
	handler := c.Protocols[pool.Protocol]
	if handler == nil {
		l.Log("bug", "true", "msg", "internal error: unknown balancer protocol!")
		return c.deleteBalancer(l, name, "internalError")
	}

	if deleteReason := handler.ShouldAnnounce(l, name, svc.TrafficPolicy, eps); deleteReason != "" {
		return c.deleteBalancer(l, name, deleteReason)
	}

	if err := handler.SetBalancer(l, name, lbIP, pool); err != nil {
		l.Log("op", "setBalancer", "error", err, "msg", "failed to announce service")
		return types.SyncStateError
	}

	if c.announced[name] == "" {
		c.announced[name] = pool.Protocol
		c.svcIP[name] = lbIP
	}

	announcing.With(prometheus.Labels{
		"protocol": string(pool.Protocol),
		"service":  name,
		"node":     c.myNode,
		"ip":       lbIP.String(),
	}).Set(1)
	l.Log("event", "serviceAnnounced", "msg", "service has IP, announcing")

	return types.SyncStateSuccess
}

func (c *Controller) deleteBalancer(l gokitlog.Logger, name, reason string) types.SyncState {
	proto, ok := c.announced[name]
	if !ok {
		return types.SyncStateSuccess
	}

	if err := c.Protocols[proto].DeleteBalancer(l, name, reason); err != nil {
		l.Log("op", "deleteBalancer", "error", err, "msg", "failed to clear balancer state")
		return types.SyncStateError
	}

	announcing.Delete(prometheus.Labels{
		"protocol": string(proto),
		"service":  name,
		"node":     c.myNode,
		"ip":       c.svcIP[name].String(),
	})
	delete(c.announced, name)
	delete(c.svcIP, name)

	l.Log("event", "serviceWithdrawn", "ip", c.svcIP[name], "reason", reason, "msg", "withdrawing service announcement")

	return types.SyncStateSuccess
}

func poolFor(pools map[string]*config.Pool, ip net.IP) string {
	for pname, p := range pools {
		for _, cidr := range p.CIDR {
			if cidr.Contains(ip) {
				return pname
			}
		}
	}
	return ""
}

func (c *Controller) SetConfig(l gokitlog.Logger, cfg *config.Config) types.SyncState {
	l.Log("event", "startUpdate", "msg", "start of config update")
	defer l.Log("event", "endUpdate", "msg", "end of config update")

	if cfg == nil {
		l.Log("op", "setConfig", "error", "no MetalLB configuration in cluster", "msg", "configuration is missing, MetalLB will not function")
		return types.SyncStateError
	}

	for svc, ip := range c.svcIP {
		if pool := poolFor(cfg.Pools, ip); pool == "" {
			l.Log("op", "setConfig", "service", svc, "ip", ip, "error", "service has no configuration under new config", "msg", "new configuration rejected")
			return types.SyncStateError
		}
	}

	for proto, handler := range c.Protocols {
		if err := handler.SetConfig(l, cfg); err != nil {
			l.Log("op", "setConfig", "protocol", proto, "error", err, "msg", "applying new configuration to protocol handler failed")
			return types.SyncStateError
		}
	}

	c.config = cfg

	return types.SyncStateReprocessAll
}

func (c *Controller) SetNode(l gokitlog.Logger, node *v1.Node) types.SyncState {
	return c.SetNodeLabels(l, node.Labels)
}

func (c *Controller) SetNodeLabels(l gokitlog.Logger, labels map[string]string) types.SyncState {
	for proto, handler := range c.Protocols {
		if err := handler.SetNodeLabels(l, labels); err != nil {
			l.Log("op", "setNode", "error", err, "protocol", proto, "msg", "failed to propagate node info to protocol handler")
			return types.SyncStateError
		}
	}
	return types.SyncStateSuccess
}

// PeerSessions returns the underlying BGP sessions from the BGP controller. In
// Layer2 mode only, this returns nil.
func (c *Controller) PeerSessions() []Session {
	if handler, ok := c.Protocols[config.BGP]; ok {
		return handler.(*BGPController).PeerSessions()
	}
	return nil
}

// Endpoints represents an object containing the minimal representation of a
// v1.Endpoints similar to Service.
type Endpoints struct {
	Ready, NotReady []Endpoint
}

func toEndpoints(in k8s.EpsOrSlices) *Endpoints {
	out := new(Endpoints)
	switch in.Type {
	case k8s.Eps:
		for _, sub := range in.EpVal.Subsets {
			for _, ep := range sub.Addresses {
				out.Ready = append(out.Ready, Endpoint{
					IP:       ep.IP,
					NodeName: ep.NodeName,
				})
			}
			for _, ep := range sub.NotReadyAddresses {
				out.NotReady = append(out.NotReady, Endpoint{
					IP:       ep.IP,
					NodeName: ep.NodeName,
				})
			}
		}
	case k8s.Slices:
		for _, slice := range in.SlicesVal {
			for _, ep := range slice.Endpoints {
				node := ep.Topology["kubernetes.io/hostname"]
				for _, addr := range ep.Addresses {
					if k8s.IsConditionReady(ep.Conditions) {
						out.Ready = append(out.Ready, Endpoint{
							IP:       addr,
							NodeName: &node,
						})
					} else {
						out.NotReady = append(out.NotReady, Endpoint{
							IP:       addr,
							NodeName: &node,
						})
					}
				}
			}
		}
	}
	return out
}

type Endpoint struct {
	IP       string
	NodeName *string
}

// A Protocol can advertise an IP address.
type Protocol interface {
	SetConfig(gokitlog.Logger, *config.Config) error
	ShouldAnnounce(gokitlog.Logger, string, string, *Endpoints) string
	SetBalancer(gokitlog.Logger, string, net.IP, *config.Pool) error
	DeleteBalancer(gokitlog.Logger, string, string) error
	SetNodeLabels(gokitlog.Logger, map[string]string) error
}

// Speakerlist represents a list of healthy speakers.
type SpeakerList interface {
	UsableSpeakers() map[string]bool
	Rejoin()
}

// Service offers methods to mutate a Kubernetes service object.
type service interface {
	UpdateStatus(svc *v1.Service) error
	Infof(svc *v1.Service, desc, msg string, args ...interface{})
	Errorf(svc *v1.Service, desc, msg string, args ...interface{})
}

var announcing = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "metallb",
	Subsystem: "speaker",
	Name:      "announced",
	Help:      "Services being announced from this node. This is desired state, it does not guarantee that the routing protocols have converged.",
}, []string{
	"service",
	"protocol",
	"node",
	"ip",
})

func init() {
	prometheus.MustRegister(announcing)
}
