// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
)

var fqdnCmd = &cobra.Command{
	Use:   "fqdn",
	Short: "Manage fqdn proxy",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var fqdnNames = &cobra.Command{
	Use:   "names",
	Short: "Show internal state Cilium has for DNS names / regexes",
	Run: func(cmd *cobra.Command, args []string) {
		listFQDNNames()
	},
}

var fqdnCacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage fqdn proxy cache",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var fqdnCleanCacheCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean fqdn cache",
	Run: func(cmd *cobra.Command, args []string) {
		cleanFQDNCache()
	},
}

var fqdnListCacheCmd = &cobra.Command{
	Use:   "list",
	Short: "List fqdn cache contents",
	Run: func(cmd *cobra.Command, args []string) {
		listFQDNCache()
	},
}

var fqdnCacheMatchPattern string
var fqdnEndpointID string
var fqdnSource string

func init() {
	fqdnCacheCmd.AddCommand(fqdnListCacheCmd)
	fqdnCacheCmd.AddCommand(fqdnCleanCacheCmd)
	fqdnCmd.AddCommand(fqdnCacheCmd)
	fqdnCmd.AddCommand(fqdnNames)
	rootCmd.AddCommand(fqdnCmd)

	fqdnCleanCacheCmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation")
	fqdnCleanCacheCmd.Flags().StringVarP(&fqdnCacheMatchPattern, "matchpattern", "p", "", "Delete cache entries with FQDNs that match matchpattern")

	fqdnListCacheCmd.Flags().StringVarP(&fqdnCacheMatchPattern, "matchpattern", "p", "", "List cache entries with FQDN that match matchpattern")
	fqdnListCacheCmd.Flags().StringVarP(&fqdnEndpointID, "endpoint", "e", "", "List cache entries for a specific endpoint id")
	fqdnListCacheCmd.Flags().StringVarP(&fqdnSource, "source", "s", "", "List cache entries from a specific source (lookup, connection)")
	command.AddOutputOption(fqdnListCacheCmd)
}

func cleanFQDNCache() {
	if !force {
		fmt.Println("Following cache entries are going to be deleted:")
		listFQDNCache()
		if !confirmCleanup() {
			return
		}
	}

	params := policy.NewDeleteFqdnCacheParams()

	if fqdnCacheMatchPattern != "" {
		params.SetMatchpattern(&fqdnCacheMatchPattern)
	}

	_, err := client.Policy.DeleteFqdnCache(params)
	if err != nil {
		Fatalf("Error: %s\n", err)
	}
	fmt.Println("FQDN proxy cache cleared")
}

func listFQDNCache() {
	var lookups []*models.DNSLookup = []*models.DNSLookup{}

	if fqdnEndpointID != "" {
		params := policy.NewGetFqdnCacheIDParams()

		if fqdnSource != "" {
			params.SetSource(&fqdnSource)
		}

		if fqdnCacheMatchPattern != "" {
			params.SetMatchpattern(&fqdnCacheMatchPattern)
		}

		if fqdnEndpointID != "" {
			params.SetID(fqdnEndpointID)
		}
		result, err := client.Policy.GetFqdnCacheID(params)
		if err != nil {
			switch err := err.(type) {
			case *policy.GetFqdnCacheIDNotFound:
				// print out empty lookups slice
			default:
				Fatalf("Error: %s\n", err)
			}
		} else {
			lookups = result.Payload
		}
	} else {
		params := policy.NewGetFqdnCacheParams()

		if fqdnSource != "" {
			params.SetSource(&fqdnSource)
		}

		if fqdnCacheMatchPattern != "" {
			params.SetMatchpattern(&fqdnCacheMatchPattern)
		}

		result, err := client.Policy.GetFqdnCache(params)
		if err != nil {
			switch err := err.(type) {
			case *policy.GetFqdnCacheNotFound:
				// print out empty lookups slice
			default:
				Fatalf("Error: %s\n", err)
			}
		} else {
			lookups = result.Payload
		}
	}

	if command.OutputOption() {
		if err := command.PrintOutput(lookups); err != nil {
			Fatalf("Unable to provide %s output: %s", command.OutputOptionString(), err)
		}
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Endpoint\tSource\tFQDN\tTTL\tExpirationTime\tIPs\t")
	for _, lookup := range lookups {
		fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\t%s\t\n",
			lookup.EndpointID,
			lookup.Source,
			lookup.Fqdn,
			lookup.TTL,
			lookup.ExpirationTime.String(),
			strings.Join(lookup.Ips, ","))
	}
	w.Flush()
}

func listFQDNNames() {
	result, err := client.Policy.GetFqdnNames(nil)
	if err != nil {
		Fatalf("Error: %s\n", err)
	}
	if err := command.PrintOutputWithType(result.Payload, "json"); err != nil {
		Fatalf("Unable to print JSON output: %s\n", err)
	}
}
