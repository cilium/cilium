// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgpv1/api"
	"github.com/cilium/cilium/pkg/bgpv1/types"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/status"
)

const (
	availableKW  = "available"
	advertisedKW = "advertised"
	vRouterKW    = "vrouter"
	peerKW       = "peer"
	neighborKW   = "neighbor"
	ipv4AFI      = "ipv4"
	unicastSAFI  = "unicast"
)

// GetRoutes gets BGP routes from all/specific cilium agent pods.
func (s *Status) GetRoutes(ctx context.Context, args []string) error {
	silent := s.params.Output == status.OutputJSON // do not print out notes / warnings when the output is JSON
	if len(args) < 1 {
		args = defaultGetRoutesArgs(silent)
	}
	err := validateGetRoutesArgs(args)
	if err != nil {
		return err
	}

	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	err = s.initTargetCiliumPods(ctx)
	if err != nil {
		return err
	}

	res, err := s.fetchRoutesConcurrently(ctx, args)
	if err != nil {
		if len(res) == 0 {
			// no results retrieved - just return the error
			return err
		}
		// print the errors, but continue with printing results
		fmt.Fprintf(os.Stderr, "Errors by retrieving routes: %v\n\n", err)
	}
	return s.writeRoutes(res)
}

func (s *Status) fetchRoutesConcurrently(ctx context.Context, args []string) (map[string][]*models.BgpRoute, error) {
	allFetchedData := make(map[string][]*models.BgpRoute)

	// res contains data returned from cilium pod
	type res struct {
		nodeName string
		data     []*models.BgpRoute
		err      error
	}
	resCh := make(chan res)

	var wg sync.WaitGroup

	// max number of concurrent go routines will be number of cilium agent pods
	wg.Add(len(s.ciliumPods))

	// compute the command for fetching the routes from a cilium pod
	fetchCmd := []string{"cilium", "bgp", "routes"}
	fetchCmd = append(fetchCmd, args...)
	fetchCmd = append(fetchCmd, "-o", "json")

	// concurrently fetch routes from each cilium pod
	for _, pod := range s.ciliumPods {
		go func(ctx context.Context, pod *corev1.Pod) {
			defer wg.Done()

			routes, err := s.fetchRoutesFromPod(ctx, fetchCmd, pod)
			resCh <- res{
				nodeName: pod.Spec.NodeName,
				data:     routes,
				err:      err,
			}
		}(ctx, pod)
	}

	// close resCh when data from all nodes is collected
	go func() {
		wg.Wait()
		close(resCh)
	}()

	// read from the channel till it is closed.
	// on error, store error and continue to next node.
	var err error
	for fetchedData := range resCh {
		if fetchedData.err != nil {
			err = errors.Join(err, fetchedData.err)
		} else {
			allFetchedData[fetchedData.nodeName] = fetchedData.data
		}
	}

	return allFetchedData, err
}

func (s *Status) fetchRoutesFromPod(ctx context.Context, fetchCmd []string, pod *corev1.Pod) ([]*models.BgpRoute, error) {
	output, errOutput, err := s.client.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, fetchCmd)
	if err != nil {
		var errStr string
		if errOutput.String() != "" {
			errStr = strings.TrimSpace(errOutput.String())
		} else {
			errStr = err.Error()
		}
		return nil, fmt.Errorf("failed to fetch bgp state from %s: (%s)", pod.Name, errStr)
	}

	bgpRoutes := make([]*models.BgpRoute, 0)

	err = json.Unmarshal(output.Bytes(), &bgpRoutes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal bgp routes from %s: %v", pod.Name, err)
	}

	return bgpRoutes, nil
}

func (s *Status) writeRoutes(res map[string][]*models.BgpRoute) error {
	if s.params.Output == status.OutputJSON {
		jsonStatus, err := json.MarshalIndent(res, "", " ")
		if err != nil {
			return err
		}
		fmt.Println(string(jsonStatus))
	} else {
		printRouteSummary(os.Stdout, res)
	}

	return nil
}

func defaultGetRoutesArgs(silent bool) []string {
	if !silent {
		fmt.Printf("(Defaulting to `%s %s %s` routes, please see help for more options)\n\n", availableKW, ipv4AFI, unicastSAFI)
	}
	return []string{availableKW, ipv4AFI, unicastSAFI}
}

func validateGetRoutesArgs(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing argument `%s` / `%s`", availableKW, advertisedKW)
	}
	// <available | advertised>
	if args[0] != availableKW && args[0] != advertisedKW {
		return fmt.Errorf("invalid argument: `%s`, expected `%s` / `%s`", args[0], availableKW, advertisedKW)
	}

	// <afi> <safi>
	if len(args) < 2 {
		return fmt.Errorf("missing AFI value (e.g. `%s`)", ipv4AFI)
	}
	if types.ParseAfi(args[1]) == types.AfiUnknown {
		return fmt.Errorf("unknown AFI `%s`", args[1])
	}
	if len(args) < 3 {
		return fmt.Errorf("missing SAFI value (e.g. `%s`)", unicastSAFI)
	}
	if types.ParseSafi(args[2]) == types.SafiUnknown {
		return fmt.Errorf("unknown SAFI `%s`", args[2])
	}
	if len(args) > 3 && (args[3] != vRouterKW && args[3] != peerKW && args[3] != neighborKW) {
		return fmt.Errorf("invalid argument: `%s`, expected `%s` / `%s`", args[3], vRouterKW, peerKW)
	}
	checkArgs := args[3:] // re-slice processed arguments

	// [vrouter <asn>]
	if len(checkArgs) > 0 && checkArgs[0] == vRouterKW {
		if len(checkArgs) < 2 {
			return fmt.Errorf("missing vrouter ASN value")
		}
		if _, err := strconv.ParseInt(checkArgs[1], 10, 64); err != nil {
			return fmt.Errorf("invalid vrouter ASN: %w", err)
		}
		checkArgs = checkArgs[2:] // re-slice processed arguments
	}

	// [peer|neighbor <address>]
	if args[0] == advertisedKW {
		if len(checkArgs) == 0 || (checkArgs[0] != peerKW && checkArgs[0] != neighborKW) {
			return fmt.Errorf("missing `%s` argument", peerKW)
		}
		if len(checkArgs) < 2 {
			return fmt.Errorf("missing peer IP address")
		}
		if _, err := netip.ParseAddr(checkArgs[1]); err != nil {
			return fmt.Errorf("invalid peer IP address: %w", err)
		}
	}
	return nil
}

func printRouteSummary(out io.Writer, routesPerNode map[string][]*models.BgpRoute) {
	// sort by node names
	var nodes []string
	for node := range routesPerNode {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)

	// sort routes per node
	for _, routes := range routesPerNode {
		// sort routes first by ASN and then by prefix
		sort.Slice(routes, func(i, j int) bool {
			return routes[i].RouterAsn < routes[j].RouterAsn || routes[i].Prefix < routes[j].Prefix
		})
	}

	w := tabwriter.NewWriter(out, minWidth, 0, padding, paddingChar, 0)
	fmt.Fprintln(w, "Node\tVRouter\tPrefix\tNextHop\tAge\tAttrs")

	for _, node := range nodes {
		routes := routesPerNode[node]

		for i, route := range routes {
			if i == 0 {
				// print name for first row of node's routes
				fmt.Fprintf(w, "%s\t", node)
			} else {
				// skip name for all rest of the routes
				fmt.Fprint(w, "\t")
			}

			r, err := api.ToAgentRoute(route)
			if err != nil {
				if i == 0 {
					fmt.Fprintf(w, "\n")
				}
				continue
			}
			for _, path := range r.Paths {
				fmt.Fprintf(w, "%d\t", route.RouterAsn)
				fmt.Fprintf(w, "%s\t", path.NLRI)
				fmt.Fprintf(w, "%s\t", nextHopFromPathAttributes(path.PathAttributes))
				fmt.Fprintf(w, "%s\t", time.Duration(path.AgeNanoseconds).Round(time.Second))
				fmt.Fprintf(w, "%s\t", path.PathAttributes)
				fmt.Fprintf(w, "\n")
			}
			if len(r.Paths) == 0 {
				fmt.Fprintf(w, "\n")
			}
		}
	}
	w.Flush()
}

func nextHopFromPathAttributes(pathAttributes []bgp.PathAttributeInterface) string {
	for _, a := range pathAttributes {
		switch attr := a.(type) {
		case *bgp.PathAttributeNextHop:
			return attr.Value.String()
		case *bgp.PathAttributeMpReachNLRI:
			return attr.Nexthop.String()
		}
	}
	return "0.0.0.0"
}
