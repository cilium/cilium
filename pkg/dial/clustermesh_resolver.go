// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dial

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	clustermeshResolverConfigMapName string = "cilium-clustermesh-clusters"
	clustermeshResolverConfigMapKey  string = "clusters.json"
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
	Domain   string `json:"domain"`
	Clusters []struct {
		Name    string       `json:"name"`
		Address string       `json:"address"`
		IPs     []netip.Addr `json:"ips"`
	} `json:"clusters"`
}

// ClustermeshResolver maps aliases for clustermeshes to their IP addresses.
type ClustermeshResolver struct {
	mu      lock.RWMutex
	records map[string]netip.Addr
}

func newClustermeshResolver(jg job.Group, client k8sClient.Clientset) *ClustermeshResolver {
	cr := &ClustermeshResolver{
		mu:      lock.RWMutex{},
		records: make(map[string]netip.Addr),
	}

	jg.Add(job.OneShot("clustermesh-clusters-configmap-watcher",
		func(ctx context.Context, health cell.Health) error {
			// TODO: What's a better way to get the namespace? This code is shared between many components.
			watcher, err := client.CoreV1().ConfigMaps("kube-system").Watch(ctx, metav1.ListOptions{
				FieldSelector:   fmt.Sprintf("metadata.name=%s", clustermeshResolverConfigMapName),
				ResourceVersion: "",
			})
			if err != nil {
				return err
			}
			health.OK("configmap watcher initialised")

			events := watcher.ResultChan()

		loop:
			for {
				select {
				case <-ctx.Done():
					break loop
				case event := <-events:
					switch event.Type {
					case watch.Added, watch.Modified:
						configMap := event.Object.(*corev1.ConfigMap)
						parsedConf := clustermeshConfig{}
						if err := json.Unmarshal([]byte(configMap.Data[clustermeshResolverConfigMapKey]), &parsedConf); err != nil {
							continue
						}
						records := make(map[string]netip.Addr)
						for _, c := range parsedConf.Clusters {
							if len(c.IPs) < 1 {
								continue
							}

							address := c.Address
							if c.Address == "" {
								address = fmt.Sprintf("%s.%s", c.Name, parsedConf.Domain)
							}
							records[address] = c.IPs[0]
						}
						cr.set(records)
					case watch.Deleted:
						cr.set(make(map[string]netip.Addr))
					default:
					}
				}
			}
			return nil
		},
	))

	return cr
}

func (cr *ClustermeshResolver) set(records map[string]netip.Addr) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.records = records
}

func (cr *ClustermeshResolver) Resolve(_ context.Context, host string) (string, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	addr, ok := cr.records[host]
	if !ok {
		return "", fmt.Errorf("clustermesh IP for %s not found", host)
	}

	return addr.Unmap().String(), nil
}
