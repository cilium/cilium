// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/identity"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	policyk8s "github.com/cilium/cilium/pkg/policy/k8s"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	policyutils "github.com/cilium/cilium/pkg/policy/utils"
	"github.com/cilium/cilium/pkg/u8proto"
)

var dummyRedirects = map[string]uint16{
	policy.FallbackRedirectID: math.MaxUint16,
}

func msStageCmd(params CmdParams) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Display resulting policy map for a proposed policy change.",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("output", "o", "table", "Format to write in (table, json)")
				fs.BoolP("diff", "d", false, "Display the difference from the existing policy map.")
				fs.StringP("endpoint", "e", "", "Endpoint, either numeric ID or <namespace/name>, to stage this policy")
				fs.StringSliceP("filename", "f", nil, "YAML or JSON policy resource to stage")
			},
			AutocompleteFlag: func(state *script.State, _ []string, flag, cur string) []string {
				switch flag {
				case "o", "output":
					return filterPrefix([]string{"table", "json"}, cur)
				case "e", "endpoint":
					return autocompleteEndpointsImpl(params, cur)
				case "f", "filename":
					return autocompleteFilenameImpl(state, cur)
				}
				return nil
			},
			Detail: []string{
				"Display the resulting mapstate for applying a given poliy to an endpoint.",
				"All existing policies are preserved unless overwritten by the proposed policy.",
				"Optionally, will display the difference between the existing policy.",
			},
		},
		func(state *script.State, args ...string) (script.WaitFunc, error) {
			return func(state *script.State) (stdout, stderr string, err error) {
				format, err := state.Flags.GetString("output")
				if err != nil {
					return "", "", err
				}
				if format != "json" && format != "table" {
					return "", "", fmt.Errorf("unsupported output format %s", format)
				}

				diff, err := state.Flags.GetBool("diff")
				if err != nil {
					return "", "", err
				}

				cmd, err := newStageCmd(params, state)
				if err != nil {
					return "", "", err
				}

				if len(cmd.toAddPaths) == 0 && diff {
					return "", "", fmt.Errorf("--filename is required")
				}

				var entriesBefore, entriesAfter map[policytypes.Key]entryOut
				if diff {
					entriesBefore, err = cmd.getEPEntries()
					if err != nil {
						return "", "", fmt.Errorf("failed to get existing policy map for endpoint: %w", err)
					}
				}

				// apply policy
				err = cmd.applyPolicies()
				if err != nil {
					return "", "", fmt.Errorf("failed to apply new policy: %w", err)
				}

				entriesAfter, err = cmd.getEPEntries()
				if err != nil {
					return "", "", fmt.Errorf("failed to compute endpoint's policy map: %w", err)
				}

				if len(entriesAfter) > params.PMFactory.PolicyMaxEntries() {
					cmd.log.Warn("Endpoint BPF policy map will overflow!",
						logfields.Limit, params.PMFactory.PolicyMaxEntries(),
						logfields.Size, len(entriesAfter),
					)
				}

				res := toResult(entriesBefore, entriesAfter)

				// generate json output
				if format == "json" {
					b, err := json.MarshalIndent(&res, "", "\t")
					if err != nil {
						return "", "", fmt.Errorf("json marshal failed: %w", err)
					}
					return string(b), "", nil
				}

				// Output table
				buf := &strings.Builder{}
				tw := tabwriter.NewWriter(buf, 5, 0, 3, ' ', 0)
				fmt.Fprintf(tw, " \tDirection\tIdentity\tProto+Port\tPriority\tListenerPrio\tVerdict\tProxied\tOrigins\n")
				if diff {
					for _, row := range res.Diff {
						if row.Deleted != nil {
							printDiffRow(tw, cmd.ids, '-', *row.Deleted)
						}
						if row.Added != nil {
							printDiffRow(tw, cmd.ids, '+', *row.Added)
						}
					}
				} else {
					for _, row := range res.MapState {
						printDiffRow(tw, cmd.ids, ' ', row)
					}
				}
				tw.Flush()
				return buf.String(), "", nil
			}, nil
		},
	)
}

type stageCmd struct {
	params CmdParams

	log *slog.Logger
	pr  *policy.Repository
	ids identity.IdentityMap

	toAddPaths []string

	ep   *endpoint.Endpoint
	epID *identity.Identity
}

type result struct {
	MapState []entryOut  `json:"mapState"`
	Diff     []diffEntry `json:"diff"`
}

type diffEntry struct {
	Deleted *entryOut `json:"deleted,omitempty"`
	Added   *entryOut `json:"added,omitempty"`
}

func newStageCmd(params CmdParams, state *script.State) (*stageCmd, error) {
	s := &stageCmd{
		params: params,
		log:    slog.New(slog.NewTextHandler(state.LogWriter(), nil)),
	}

	var err error
	s.toAddPaths, err = state.Flags.GetStringSlice("filename")
	if err != nil {
		return nil, err
	}

	epSpec, _ := state.Flags.GetString("endpoint")
	if epSpec == "" {
		return nil, fmt.Errorf("endpoint is required")
	}

	eps, _ := lookupEPs(params.EPL, []string{epSpec})
	if len(eps) != 1 {
		return nil, fmt.Errorf("endpoint not found!")
	}
	s.ep = eps[0]
	s.epID, err = s.ep.GetSecurityIdentity()
	if err != nil {
		return nil, err
	}

	pr := params.Repository.(*policy.Repository)
	if pr == nil {
		return nil, fmt.Errorf("BUG: could not cast policy repository")
	}
	// Take a snapshot of the repository so we can make changes
	s.pr, s.ids = pr.Snapshot(s.log,
		&mockCertificateManager{},
		envoypolicy.NewEnvoyL7RulesTranslator(s.log, certificatemanager.NewMockSecretManagerSDS()))

	// add this endpoint to the subject selector cache
	wg := sync.WaitGroup{}
	s.pr.GetSubjectSelectorCache().UpdateIdentities(identity.IdentityMap{s.epID.ID: s.epID.LabelArray}, nil, &wg)
	wg.Wait()

	return s, nil
}

// applyPolicy applies the given policy to the repository
func (s *stageCmd) applyPolicies() error {
	for _, path := range s.toAddPaths {
		// Parse policy file, then apply to repository.
		fp, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", path, err)
		}

		decoder := yaml.NewYAMLOrJSONDecoder(fp, 4096)
		applied := false
		for {
			u := unstructured.Unstructured{}
			if err := decoder.Decode(&u); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("failed to parse policy: %w", err)
			}
			if err := s.applyPolicy(&u); err != nil {
				return err
			}
			applied = true
		}

		if !applied {
			return fmt.Errorf("policy file %s was empty", path)
		}
	}
	return nil
}

type makeEntriesFunc func(s *stageCmd, obj *unstructured.Unstructured) (policytypes.PolicyEntries, ipcacheTypes.ResourceKind, error)

var makeEntriesFuncs = map[schema.GroupKind]makeEntriesFunc{
	{Group: "cilium.io", Kind: ciliumv2.CNPKindDefinition}:  makeCNPEntries,
	{Group: "cilium.io", Kind: ciliumv2.CCNPKindDefinition}: makeCNPEntries,
	{Group: "networking.k8s.io", Kind: "NetworkPolicy"}:     makeKNPEntries,
}

// applyPolicy inserts the policy in to the repository
func (s *stageCmd) applyPolicy(obj *unstructured.Unstructured) error {
	// Sometimes we get an empty object -- ignore
	if obj.GetKind() == "" {
		return nil
	}

	policyDescription := fmt.Sprintf("%s %s/%s", obj.GroupVersionKind().Kind, obj.GetNamespace(), obj.GetName())

	toEntriesFunc, ok := makeEntriesFuncs[obj.GroupVersionKind().GroupKind()]
	if !ok {
		s.log.Warn("Non-policy type in yaml, ignoring", logfields.PolicyID, policyDescription)
		return nil
	}

	entries, resourceKind, err := toEntriesFunc(s, obj)
	if err != nil {
		return fmt.Errorf("could not parse policy %s: %w", policyDescription, err)
	}

	// allocate CIDR identities
	s.ensureCIDRIdentities(entries)

	// Insert in to policy repository
	resourceID := ipcacheTypes.NewResourceID(
		resourceKind,
		obj.GetNamespace(),
		obj.GetName(),
	)
	ids, _, _ := s.pr.ReplaceByResource(entries, resourceID)
	if !ids.Has(s.ep.GetIdentity()) {
		s.log.Warn("Supplied policy does not select endpoint!", logfields.PolicyID, policyDescription)
	}
	s.log.Info("Successfully applied policy", logfields.PolicyID, policyDescription)

	return nil
}

func makeCNPEntries(s *stageCmd, obj *unstructured.Unstructured) (policytypes.PolicyEntries, ipcacheTypes.ResourceKind, error) {
	clusterName := cmtypes.LocalClusterNameForPolicies(s.params.ClusterMeshPolicyConfig, s.params.Config.ClusterName)
	// parse to CNP
	cnp := ciliumv2.CiliumNetworkPolicy{}
	if err := convertInto(obj, &cnp); err != nil {
		return nil, "", err
	}
	resourceKind := ipcacheTypes.ResourceKindCNP
	if obj.GroupVersionKind().Kind == "CiliumClusterwideNetworkPolicy" {
		resourceKind = ipcacheTypes.ResourceKindCCNP
	} else if cnp.Namespace == "" {
		cnp.Namespace = s.ep.GetK8sNamespace()
	}

	// Translate ToServices
	policyk8s.ResolveToServices(s.params.DB.ReadTxn(), s.params.Services, s.params.Backends, &cnp)
	rules, err := cnp.Parse(s.log, clusterName)
	if err != nil {
		return nil, "", err
	}
	entries := policyutils.RulesToPolicyEntries(rules)
	return entries, resourceKind, nil
}

func makeKNPEntries(s *stageCmd, obj *unstructured.Unstructured) (policytypes.PolicyEntries, ipcacheTypes.ResourceKind, error) {
	clusterName := cmtypes.LocalClusterNameForPolicies(s.params.ClusterMeshPolicyConfig, s.params.Config.ClusterName)
	knp := slim_networkingv1.NetworkPolicy{}
	if err := convertInto(obj, &knp); err != nil {
		return nil, "", err
	}
	if knp.Namespace == "" {
		knp.Namespace = s.ep.GetK8sNamespace()
	}

	entries, err := k8s.ParseNetworkPolicy(s.log, clusterName, &knp)
	if err != nil {
		return nil, "", err
	}
	return entries, ipcacheTypes.ResourceKindNetpol, nil
}

// getExistingEntries evaluates the policy state as-is for the given endpoint,
func (s *stageCmd) getEPEntries() (map[policytypes.Key]entryOut, error) {
	sp, err := s.pr.ResolvePolicy(s.epID)
	if err != nil {
		return nil, err
	}

	owner := &dummyPolicyOwner{
		log: s.log,
		ep:  s.ep,
	}
	epp := sp.DistillPolicy(s.log, owner, dummyRedirects)
	epp.Ready()
	epp.Detach(s.log)
	sp.Detach()

	out := make(map[policytypes.Key]entryOut, epp.Len())
	for key, entry := range epp.Entries() {
		entry.Cookie = 0 // don't want to compare cookie
		meta, _ := epp.GetRuleMeta(key)
		out[key] = makeEntry(key, entry, meta)
	}

	return out, nil
}

// ensureCIDRIdentities emulates allocating identities for CIDR selectors.
//
// It just tweaks the SelectorCache, it doesn't actually allocate any identities.
//
// Horribly slow, but this is for interactive use, so it should be OK
func (s *stageCmd) ensureCIDRIdentities(e policytypes.PolicyEntries) {
	prefixes := policy.GetCIDRPrefixes(e)

	toAllocate := identity.IdentityMap{}

	// For every prefix, see if the IDMap already has an identity with exactly
	// this CIDR
prefixLoop:
	for _, prefix := range prefixes {
		lbls := labels.GetCIDRLabelArray(prefix)
		wantLabel := lbls[0]
		for _, existingLabels := range s.ids {
			for _, existingLbl := range existingLabels {
				if existingLbl.Equals(&wantLabel) {
					continue prefixLoop
				}
			}
		}

		// Need to allocate a new identity for this CIDR
		for nid := identity.MinLocalIdentity; nid < identity.MaxLocalIdentity; nid++ {
			if _, exists := s.ids[nid]; exists {
				continue
			}

			toAllocate[nid] = lbls
			s.ids[nid] = lbls
			break
		}
	}

	// Insert allocated identities in to the wait group
	wg := sync.WaitGroup{}
	s.pr.GetSelectorCache().UpdateIdentities(toAllocate, nil, &wg)
	wg.Wait()
}

// convertInto converts an object using JSON
func convertInto(input, output runtime.Object) error {
	b, err := json.Marshal(input)
	if err != nil {
		return err // unreachable
	}
	return parseInto(b, output)
}

func parseInto(b []byte, output runtime.Object) error {
	_, _, err := serializer.NewCodecFactory(scheme.Scheme, serializer.EnableStrict).UniversalDeserializer().Decode(b, nil, output)
	return err
}

func toResult(before, after map[policytypes.Key]entryOut) result {
	out := result{}

	for _, newEntry := range after {
		out.MapState = append(out.MapState, newEntry)
	}
	if before == nil {
		return out
	}

	for k, newEntry := range after {
		oldEntry, exists := before[k]
		if !exists { // net-new entry
			out.Diff = append(out.Diff, diffEntry{Added: &newEntry})
		} else if oldEntry.mse != newEntry.mse { // different datapath entry
			out.Diff = append(out.Diff, diffEntry{Deleted: &oldEntry, Added: &newEntry})
		}
	}

	for k, oldEntry := range before {
		_, exists := after[k]
		if !exists {
			out.Diff = append(out.Diff, diffEntry{Deleted: &oldEntry})
		}
	}
	return out
}

func printDiffRow(tw *tabwriter.Writer, idm identity.IdentityMap, sigil rune, row entryOut) {
	id := "unknown"
	if row.Identity == 0 {
		id = "*"
	}
	if lbls, ok := idm[row.Identity]; ok {
		id = lbls.String()
	}

	fmt.Fprintf(tw, "%c\t%s\t%s\t%s\t%d\t%d\t%s\t%t\t%s\n",
		sigil,
		row.Direction,
		id,
		row.PortProto,
		row.Priority,
		row.ListenerPriority,
		row.Verdict,
		row.ProxyPort != 0,
		joinOrigins(row.Origins),
	)
}

type mockCertificateManager struct{}

func (_ *mockCertificateManager) GetTLSContext(ctx context.Context, tlsCtx *api.TLSContext, ns string) (ca, public, private string, inlineSecrets bool, err error) {
	return "", "", "", false, nil // standard SDS response
}

// dummyPolicyOwner wraps an endpoint, intercepting side-effecting calls
type dummyPolicyOwner struct {
	log *slog.Logger
	ep  *endpoint.Endpoint
}

var _ policy.PolicyOwner = (*dummyPolicyOwner)(nil)

func (o *dummyPolicyOwner) GetID() uint64 {
	return o.ep.GetID()
}

func (o *dummyPolicyOwner) GetIngressNamedPort(name string, proto u8proto.U8proto) uint16 {
	return o.ep.GetIngressNamedPort(name, proto)
}

func (o *dummyPolicyOwner) PolicyDebug(msg string, attrs ...any) {
	if o.log != nil {
		o.log.Debug(msg, attrs...)
	}
}

func (o *dummyPolicyOwner) IsHost() bool {
	return o.ep.IsHost()
}

func (o *dummyPolicyOwner) PreviousMapState() *policy.MapState {
	return o.ep.PreviousMapState()
}

func (o *dummyPolicyOwner) RegenerateIfAlive(regenMetadata *regeneration.ExternalRegenerationMetadata) <-chan bool {
	out := make(chan bool)
	close(out)
	return out
}
