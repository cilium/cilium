// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ipmasq"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipmasq")

	// The following reserved by RFCs IP addr ranges are used by
	// https://github.com/kubernetes-sigs/ip-masq-agent
	defaultNonMasqCIDRs = map[string]net.IPNet{
		"10.0.0.0/8":      mustParseCIDR("10.0.0.0/8"),
		"172.16.0.0/12":   mustParseCIDR("172.16.0.0/12"),
		"192.168.0.0/16":  mustParseCIDR("192.168.0.0/16"),
		"100.64.0.0/10":   mustParseCIDR("100.64.0.0/10"),
		"192.0.0.0/24":    mustParseCIDR("192.0.0.0/24"),
		"192.0.2.0/24":    mustParseCIDR("192.0.2.0/24"),
		"192.88.99.0/24":  mustParseCIDR("192.88.99.0/24"),
		"198.18.0.0/15":   mustParseCIDR("198.18.0.0/15"),
		"198.51.100.0/24": mustParseCIDR("198.51.100.0/24"),
		"203.0.113.0/24":  mustParseCIDR("203.0.113.0/24"),
		"240.0.0.0/4":     mustParseCIDR("240.0.0.0/4"),
	}
	linkLocalCIDRStr = "169.254.0.0/16"
	linkLocalCIDR    = mustParseCIDR(linkLocalCIDRStr)
)

// ipnet is a wrapper type for net.IPNet to enable de-serialization of CIDRs
type Ipnet net.IPNet

func (c *Ipnet) UnmarshalJSON(json []byte) error {
	str := string(json)

	if json[0] != '"' {
		return fmt.Errorf("Invalid CIDR: %s", str)
	}

	n, err := parseCIDRv4(strings.Trim(str, `"`))
	if err != nil {
		return err
	}

	*c = Ipnet(*n)
	return nil
}

func parseCIDRv4(c string) (*net.IPNet, error) {
	ip, n, err := net.ParseCIDR(c)
	if err != nil {
		return nil, fmt.Errorf("Invalid CIDR %s: %s", c, err)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("Invalid CIDR %s: only IPv4 is supported", c)
	}
	return n, nil
}

// config represents the ip-masq-agent configuration file encoded as YAML
type config struct {
	NonMasqCIDRs  []Ipnet `json:"nonMasqueradeCIDRs"`
	MasqLinkLocal bool    `json:"masqLinkLocal"`
}

// IPMasqMap is an interface describing methods for manipulating an ipmasq map
type IPMasqMap interface {
	Update(cidr net.IPNet) error
	Delete(cidr net.IPNet) error
	Dump() ([]net.IPNet, error)
}

// IPMasqAgent represents a state of the ip-masq-agent
type IPMasqAgent struct {
	configPath             string
	masqLinkLocal          bool
	nonMasqCIDRsFromConfig map[string]net.IPNet
	nonMasqCIDRsInMap      map[string]net.IPNet
	ipMasqMap              IPMasqMap
	watcher                *fsnotify.Watcher
	stop                   chan struct{}
	handlerFinished        chan struct{}
}

func NewIPMasqAgent(configPath string) (*IPMasqAgent, error) {
	return newIPMasqAgent(configPath, &ipmasq.IPMasqBPFMap{})
}

func newIPMasqAgent(configPath string, ipMasqMap IPMasqMap) (*IPMasqAgent, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("Failed to create fsnotify watcher: %s", err)
	}

	configDir := filepath.Dir(configPath)
	// The directory of the config should exist at this time, otherwise
	// the watcher will fail to add
	if err := watcher.Add(configDir); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("Failed to add %q dir to fsnotify watcher: %s", configDir, err)
	}

	a := &IPMasqAgent{
		configPath:             configPath,
		nonMasqCIDRsFromConfig: map[string]net.IPNet{},
		nonMasqCIDRsInMap:      map[string]net.IPNet{},
		ipMasqMap:              ipMasqMap,
		watcher:                watcher,
	}

	return a, nil
}

// Start starts the ip-masq-agent goroutine which tracks the config file and
// updates the BPF map accordingly.
func (a *IPMasqAgent) Start() {
	if err := a.restore(); err != nil {
		log.WithError(err).Warn("Failed to restore")
	}
	if err := a.Update(); err != nil {
		log.WithError(err).Warn("Failed to update")
	}

	a.stop = make(chan struct{})
	a.handlerFinished = make(chan struct{})

	go func() {
		for {
			select {
			case event := <-a.watcher.Events:
				log.Debugf("Received fsnotify event: %+v", event)

				switch {
				case event.Has(fsnotify.Create),
					event.Has(fsnotify.Write),
					event.Has(fsnotify.Chmod),
					event.Has(fsnotify.Remove),
					event.Has(fsnotify.Rename):
					if err := a.Update(); err != nil {
						log.WithError(err).Warn("Failed to update")
					}
				default:
					log.Warnf("Watcher received unknown event: %s. Ignoring.", event)
				}
			case err := <-a.watcher.Errors:
				log.WithError(err).Warn("Watcher received an error")
			case <-a.stop:
				log.Info("Stopping ip-masq-agent")
				close(a.handlerFinished)
				return
			}
		}
	}()
}

// Stop stops the ip-masq-agent goroutine and the watcher.
func (a *IPMasqAgent) Stop() {
	close(a.stop)
	<-a.handlerFinished
	a.watcher.Close()
}

// Update updates the ipmasq BPF map entries with ones from the config file.
func (a *IPMasqAgent) Update() error {
	isEmpty, err := a.readConfig()
	if err != nil {
		return err
	}

	// Set default nonMasq CIDRS if user hasn't specified any
	if isEmpty {
		for cidrStr, cidr := range defaultNonMasqCIDRs {
			a.nonMasqCIDRsFromConfig[cidrStr] = cidr
		}
	}

	if !a.masqLinkLocal {
		a.nonMasqCIDRsFromConfig[linkLocalCIDRStr] = linkLocalCIDR
	}

	for cidrStr, cidr := range a.nonMasqCIDRsFromConfig {
		if _, ok := a.nonMasqCIDRsInMap[cidrStr]; !ok {
			log.WithField(logfields.CIDR, cidrStr).Info("Adding CIDR")
			a.ipMasqMap.Update(cidr)
			a.nonMasqCIDRsInMap[cidrStr] = cidr
		}
	}

	for cidrStr, cidr := range a.nonMasqCIDRsInMap {
		if _, ok := a.nonMasqCIDRsFromConfig[cidrStr]; !ok {
			log.WithField(logfields.CIDR, cidrStr).Info("Removing CIDR")
			a.ipMasqMap.Delete(cidr)
			delete(a.nonMasqCIDRsInMap, cidrStr)
		}
	}

	return nil
}

// readConfig reads the config file and populates IPMasqAgent.nonMasqCIDRsFromConfig
// with the CIDRs from the file.
func (a *IPMasqAgent) readConfig() (bool, error) {
	var cfg config

	raw, err := os.ReadFile(a.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.WithField(logfields.Path, a.configPath).Info("Config file not found")
			a.nonMasqCIDRsFromConfig = map[string]net.IPNet{}
			a.masqLinkLocal = false
			return true, nil
		}
		return false, fmt.Errorf("Failed to read %s: %s", a.configPath, err)
	}

	if len(raw) == 0 {
		a.nonMasqCIDRsFromConfig = map[string]net.IPNet{}
		a.masqLinkLocal = false
		return true, nil
	}

	jsonStr, err := yaml.ToJSON(raw)
	if err != nil {
		return false, fmt.Errorf("Failed to convert to json: %s", err)
	}

	if err := json.Unmarshal(jsonStr, &cfg); err != nil {
		return false, fmt.Errorf("Failed to de-serialize json: %s", err)
	}

	nonMasqCIDRs := map[string]net.IPNet{}
	for _, cidr := range cfg.NonMasqCIDRs {
		n := net.IPNet(cidr)
		nonMasqCIDRs[n.String()] = n
	}
	a.nonMasqCIDRsFromConfig = nonMasqCIDRs
	a.masqLinkLocal = cfg.MasqLinkLocal

	return false, nil
}

// restore dumps the ipmasq BPF map and populates IPMasqAgent.nonMasqCIDRsInMap
// with the CIDRs from the map.
func (a *IPMasqAgent) restore() error {
	cidrsInMap, err := a.ipMasqMap.Dump()
	if err != nil {
		return fmt.Errorf("Failed to dump ip-masq-agent cidrs from map: %s", err)
	}

	cidrs := map[string]net.IPNet{}
	for _, cidr := range cidrsInMap {
		cidrs[cidr.String()] = cidr
	}
	a.nonMasqCIDRsInMap = cidrs

	return nil
}

func mustParseCIDR(c string) net.IPNet {
	n, err := parseCIDRv4(c)
	if err != nil {
		panic(err)
	}
	return *n
}
