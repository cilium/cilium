// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dial

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"os"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"gopkg.in/yaml.v3"

	"github.com/cilium/cilium/pkg/lock"
)

// ClustermeshResolverCell provides a ClustermeshResolver instance to map DNS names
// matching clustermesh hosts to IP addresses provided in a configmap.
var ClustermeshResolverCell = cell.Module(
	"clustermesh-resolver",
	"ClustermeshResolver maps aliases for clustermeshes to their IP addresses",

	cell.Provide(newClustermeshResolver),
)

var _ Resolver = (*ClustermeshResolver)(nil)

type clustermeshConfig struct {
	Endpoints []string     `json:"endpoints"`
	IPs       []netip.Addr `json:"ips"`
}

type record struct {
	name string
	ips  []netip.Addr
}

// ClustermeshResolver maps aliases for clustermeshes to their IP addresses.
type ClustermeshResolver struct {
	mu      lock.RWMutex
	records map[string]record
}

func newClustermeshResolver(jg job.Group) *ClustermeshResolver {
	cr := &ClustermeshResolver{
		mu:      lock.RWMutex{},
		records: make(map[string]record),
	}

	return cr
}

func (cr *ClustermeshResolver) Set(name, path string) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	b, err := os.ReadFile(path)
	if err != nil {
		return
	}

	cmc := &clustermeshConfig{}
	err = yaml.Unmarshal(b, cmc)
	if err != nil {
		return
	}

	for _, endpoint := range cmc.Endpoints {
		fqdnURL, err := url.Parse(endpoint)
		if err != nil {
			continue
		}

		cr.records[fqdnURL.Hostname()] = record{name: name, ips: cmc.IPs}
	}
}

func (cr *ClustermeshResolver) Remove(name string) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	for fqdn, record := range cr.records {
		if record.name == name {
			delete(cr.records, fqdn)
		}
	}
}

func (cr *ClustermeshResolver) Resolve(_ context.Context, host string) (string, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	record, ok := cr.records[host]
	if !ok {
		return "", fmt.Errorf("clustermesh IP for %s not found", host)
	}

	if len(record.ips) < 1 {
		return "", fmt.Errorf("clustermesh IP for %s not found", host)
	}

	return record.ips[0].Unmap().String(), nil
}
