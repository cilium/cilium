// Copyright 2020 Authors of Cilium
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
	"fmt"

	"github.com/spf13/cobra"
)

func newCmdContext() *cobra.Command {
	cmd := &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Context: %s\n", k8sClient.RawConfig.CurrentContext)

			if context, ok := k8sClient.RawConfig.Contexts[k8sClient.RawConfig.CurrentContext]; ok {
				fmt.Printf("Cluster: %s\n", context.Cluster)
				fmt.Printf("Auth: %s\n", context.AuthInfo)

				if cluster, ok := k8sClient.RawConfig.Clusters[context.Cluster]; ok {
					fmt.Printf("Host: %s\n", cluster.Server)
					fmt.Printf("TLS server name: %s\n", cluster.TLSServerName)
					fmt.Printf("CA path: %s\n", cluster.CertificateAuthority)
				} else {
					fmt.Printf("❌ Cluster %s not found in configuration\n", context.Cluster)
				}
			} else {
				fmt.Printf("❌ Context %s not found in configuration\n", k8sClient.RawConfig.CurrentContext)
			}
		},
		Use:   "context",
		Short: "Display the configuration context",
	}

	return cmd
}
