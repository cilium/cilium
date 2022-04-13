// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newCmdContext() *cobra.Command {
	cmd := &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {
			if contextName == "" {
				contextName = k8sClient.RawConfig.CurrentContext
			}

			fmt.Printf("Context: %s\n", contextName)

			if context, ok := k8sClient.RawConfig.Contexts[contextName]; ok {
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
				fmt.Printf("❌ Context %s not found in configuration\n", contextName)
			}
		},
		Use:   "context",
		Short: "Display the configuration context",
	}

	return cmd
}
