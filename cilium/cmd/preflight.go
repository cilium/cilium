// Copyright 2019-2020 Authors of Cilium
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

package cmd

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/option"
	policyAPI "github.com/cilium/cilium/pkg/policy/api"

	"github.com/spf13/cobra"
)

const (
	toFQDNsPreCachePathOption = "tofqdns-pre-cache"
	toFQDNsPreCacheTTLOption  = "tofqdns-pre-cache-ttl"
)

var (
	toFQDNsPreCachePath string
	toFQDNsPreCacheTTL  int

	k8sAPIServer      string
	k8sKubeConfigPath string
)

// preflightCmd is the command used to manage preflight tasks for upgrades
var preflightCmd = &cobra.Command{
	Use:   "preflight",
	Short: "cilium upgrade helper",
	Long:  `CLI to help upgrade cilium`,
}

// pollerC, is the command used to upgrade a fqdn poller
var pollerCmd = &cobra.Command{
	Use:   "fqdn-poller",
	Short: "Prepare for DNS Polling upgrades to cilium 1.4",
	Long: `Prepare for DNS Polling upgrades to cilium 1.4 by creating a
placeholder --tofqdns-pre-cache file that can be used to pre-seed the DNS
cached used in toFQDNs rules. This is useful when upgrading cilium with
DNS Polling policies where an interruption in allowed IPs is undesirable. It
may also be used when switching from DNS Polling based DNS discovery to DNS
Proxy based discovery where an endpoint may not make a DNS request soon
enough to be used by toFQDNs policy rules`,
	Run: func(cmd *cobra.Command, args []string) {
		preflightPoller()
	},
}

func init() {
	pollerCmd.Flags().StringVar(&toFQDNsPreCachePath, toFQDNsPreCachePathOption, "", "The path to write serialized ToFQDNs pre-cache information. stdout is the default")
	pollerCmd.Flags().IntVar(&toFQDNsPreCacheTTL, toFQDNsPreCacheTTLOption, 604800, "TTL, in seconds, to set on generated ToFQDNs pre-cache information")
	preflightCmd.AddCommand(pollerCmd)

	// From preflight_migrate_crd_identity.go
	migrateIdentityCmd.Flags().StringVar(&k8sAPIServer, "k8s-api-server", "", "Kubernetes api address server (for https use --k8s-kubeconfig-path instead)")
	migrateIdentityCmd.Flags().StringVar(&k8sKubeConfigPath, "k8s-kubeconfig-path", "", "Absolute path of the kubernetes kubeconfig file")
	migrateIdentityCmd.Flags().StringVar(&kvStore, "kvstore", "", "Key-value store type")
	migrateIdentityCmd.Flags().Var(option.NewNamedMapOptions("kvstore-opts", &kvStoreOpts, nil), "kvstore-opt", "Key-value store options")
	preflightCmd.AddCommand(migrateIdentityCmd)

	validateCNP.Flags().StringVar(&k8sAPIServer, "k8s-api-server", "", "Kubernetes api address server (for https use --k8s-kubeconfig-path instead)")
	validateCNP.Flags().StringVar(&k8sKubeConfigPath, "k8s-kubeconfig-path", "", "Absolute path of the kubernetes kubeconfig file")
	preflightCmd.AddCommand(validateCNP)

	rootCmd.AddCommand(preflightCmd)
}

// preflightPoller collects IP data in toCIDRSet rules that are siblings to
// toFQDNs rules. These can only be created by toFQDNs updates and correspond
// to the matchName entries in that egressRule (the API rejects rules with two
// L3 components like this). This data is turned into json parsable by
// fqdn.DNSCache UnmarshalJSON.
func preflightPoller() {
	lookupTime := time.Now()

	// Get data from the local cilium-agent
	DNSData, err := getDNSMappings()
	if err != nil {
		Fatalf("Cannot extract DNS data from local cilium-agent: %s", err)
	}

	// Build a cache from this data to be serialized
	cache := fqdn.NewDNSCache(0)
	for name, IPs := range DNSData {
		cache.Update(lookupTime, name, IPs, toFQDNsPreCacheTTL)
	}

	// Marshal into a writeable format
	serialized, err := json.Marshal(cache)
	if err != nil {
		Fatalf("Cannot create DNS pre-cache data from policy DNS data: %s", err)
	}

	var outWriter io.WriteCloser = os.Stdout
	if toFQDNsPreCachePath != "" {
		outWriter, err = os.OpenFile(toFQDNsPreCachePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
		if err != nil {
			Fatalf("Cannot open target destination for DNS pre-cache data: %s", err)
		}
	}
	defer outWriter.Close()
	if _, err = outWriter.Write(serialized); err != nil {
		Fatalf("Error writing data: %s", err)
	}
}

// getDNSMappings reads the policy from a local agent via its API and collects
// the IPs seen for each matchName.
// Note: No attempt is made to ensure an IP belongs only to one/the correct
// matchName. In cases where different sets of matchNames are used, each with a
// different combination of names, the IPs set per name will reflects IPs that
// actuall belong to other names also seen in the toFQDNs section of that rule.
func getDNSMappings() (DNSData map[string][]net.IP, err error) {
	policy, err := client.PolicyGet(nil)
	if err != nil {
		return nil, err
	}

	var rules policyAPI.Rules
	if err := json.Unmarshal([]byte(policy.Policy), &rules); err != nil {
		return nil, err
	}

	// for each egressrule, when ToFQDNs.matchName is filled in, use the IPs we
	// inserted into that rule as IPs for that DNS name (this may be shared by many
	// DNS names). We ensure that we only read /32 CIDRs, since we only ever insert
	// those.
	DNSData = make(map[string][]net.IP)
	for _, rule := range rules {
		for _, egressRule := range rule.Egress {
			for _, ToFQDN := range egressRule.ToFQDNs {
				// nothing to do when no matchName exists or there are no IPs in this
				// rule
				if ToFQDN.MatchName == "" || len(egressRule.ToCIDRSet) == 0 {
					continue
				}
				for _, cidr := range egressRule.ToCIDRSet {
					ip, _, err := net.ParseCIDR(string(cidr.Cidr))
					if err != nil {
						return nil, err
					}
					name := matchpattern.Sanitize(ToFQDN.MatchName)
					DNSData[name] = append(DNSData[name], ip)
				}
			}
		}
	}

	return DNSData, nil
}
