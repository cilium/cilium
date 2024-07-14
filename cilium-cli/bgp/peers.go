// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/status"
)

const (
	padding     = 3
	minWidth    = 5
	paddingChar = ' '
)

// GetPeeringState gets peering state from all/specific cilium agent pods.
func (s *Status) GetPeeringState(ctx context.Context) error {
	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	err := s.initTargetCiliumPods(ctx)
	if err != nil {
		return err
	}

	res, err := s.fetchPeeringStateConcurrently(ctx)
	if err != nil {
		return err
	}

	return s.writeStatus(res)
}

func (s *Status) fetchPeeringStateConcurrently(ctx context.Context) (map[string][]*models.BgpPeer, error) {
	allFetchedData := make(map[string][]*models.BgpPeer)

	// res contains data returned from cilium pod
	type res struct {
		nodeName string
		data     []*models.BgpPeer
		err      error
	}
	resCh := make(chan res)

	var wg sync.WaitGroup

	// max number of concurrent go routines will be number of cilium agent pods
	wg.Add(len(s.ciliumPods))

	// concurrently fetch state from each cilium pod
	for _, pod := range s.ciliumPods {
		go func(ctx context.Context, pod *corev1.Pod) {
			defer wg.Done()

			peers, err := s.fetchPeeringStateFromPod(ctx, pod)
			resCh <- res{
				nodeName: pod.Spec.NodeName,
				data:     peers,
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

func (s *Status) fetchPeeringStateFromPod(ctx context.Context, pod *corev1.Pod) ([]*models.BgpPeer, error) {
	cmd := []string{"cilium", "bgp", "peers", "-o", "json"}
	output, err := s.client.ExecInPod(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bgp state from %s: %w", pod.Name, err)
	}

	bgpPeers := make([]*models.BgpPeer, 0)

	err = json.Unmarshal(output.Bytes(), &bgpPeers)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal bgp state from %s: %w", pod.Name, err)
	}

	return bgpPeers, nil
}

func (s *Status) writeStatus(res map[string][]*models.BgpPeer) error {
	if s.params.Output == status.OutputJSON {
		jsonStatus, err := json.MarshalIndent(res, "", " ")
		if err != nil {
			return err
		}
		fmt.Println(string(jsonStatus))
	} else {
		printSummary(os.Stdout, res)
	}

	return nil
}

func printSummary(out io.Writer, peersPerNode map[string][]*models.BgpPeer) {
	// sort by node names
	var nodes []string
	for node := range peersPerNode {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)

	// sort peers per node
	for _, peers := range peersPerNode {
		// sort by local AS, if peers from same AS then sort by peer address.
		sort.Slice(peers, func(i, j int) bool {
			return peers[i].LocalAsn < peers[j].LocalAsn || peers[i].PeerAddress < peers[j].PeerAddress
		})
	}

	// tab writer with min width 5 and padding 3
	w := tabwriter.NewWriter(out, minWidth, 0, padding, paddingChar, 0)
	fmt.Fprintln(w, "Node\tLocal AS\tPeer AS\tPeer Address\tSession State\tUptime\tFamily\tReceived\tAdvertised")

	for _, node := range nodes {
		peers := peersPerNode[node]

		for i, peer := range peers {
			if i == 0 {
				// print name for first row of peers
				fmt.Fprintf(w, "%s\t", node)
			} else {
				// skip name for all rest of the peers
				fmt.Fprint(w, "\t")
			}

			fmt.Fprintf(w, "%d\t", peer.LocalAsn)
			fmt.Fprintf(w, "%d\t", peer.PeerAsn)
			fmt.Fprintf(w, "%s\t", peer.PeerAddress)
			fmt.Fprintf(w, "%s\t", peer.SessionState)
			fmt.Fprintf(w, "%s\t", time.Duration(peer.UptimeNanoseconds).Round(time.Second).String())

			for j, afisafi := range peer.Families {
				if j > 0 {
					// skip space for session info
					fmt.Fprint(w, strings.Repeat("\t", 6))
				}

				fmt.Fprintf(w, "%s/%s\t", afisafi.Afi, afisafi.Safi)
				fmt.Fprintf(w, "%d\t", afisafi.Received)
				fmt.Fprintf(w, "%d\t", afisafi.Advertised)
				fmt.Fprintf(w, "\n")
			}
		}
	}
	w.Flush()
}
