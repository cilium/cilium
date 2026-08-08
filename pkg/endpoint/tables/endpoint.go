// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/identity"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8stypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/types"
)

const EndpointTableName = "managed-endpoints"

type EndpointKeyKind string

const (
	EndpointKeyKindK8s    EndpointKeyKind = "k8s"
	EndpointKeyKindGlobal EndpointKeyKind = "global"
	EndpointKeyKindIP     EndpointKeyKind = "ip"
)

type EndpointKey struct {
	Kind       EndpointKeyKind
	Cluster    string
	Namespace  string
	Name       string
	NodeName   string
	EndpointID string
	IP         netip.Prefix
}

func K8sEndpointKey(cluster, namespace, name string) EndpointKey {
	return EndpointKey{Kind: EndpointKeyKindK8s, Cluster: cluster, Namespace: namespace, Name: name}
}

func GlobalEndpointKey(cluster, nodeName, endpointID string) EndpointKey {
	return EndpointKey{Kind: EndpointKeyKindGlobal, Cluster: cluster, NodeName: nodeName, EndpointID: endpointID}
}

func IPEndpointKey(cluster string, ip netip.Prefix) EndpointKey {
	return EndpointKey{Kind: EndpointKeyKindIP, Cluster: cluster, IP: ip}
}

func (k EndpointKey) IsZero() bool {
	return k.Kind == ""
}

func (k EndpointKey) String() string {
	switch k.Kind {
	case EndpointKeyKindK8s:
		return fmt.Sprintf("%s:%s/%s/%s", k.Kind, k.Cluster, k.Namespace, k.Name)
	case EndpointKeyKindGlobal:
		return fmt.Sprintf("%s:%s/%s/%s", k.Kind, k.Cluster, k.NodeName, k.EndpointID)
	case EndpointKeyKindIP:
		return fmt.Sprintf("%s:%s/%s", k.Kind, k.Cluster, k.IP.String())
	default:
		return ""
	}
}

type SourceKind string

const (
	SourceKindCEP     SourceKind = "cep"
	SourceKindCES     SourceKind = "ces"
	SourceKindKVStore SourceKind = "kvstore"
)

type SourceKey string

func CEPSourceKey(cluster, namespace, name, uid string) SourceKey {
	return SourceKey(fmt.Sprintf("%s:%s/%s/%s/%s", SourceKindCEP, cluster, namespace, name, uid))
}

func CESSourceKey(cluster, cesName, namespace, endpointName, podUID string) SourceKey {
	return SourceKey(fmt.Sprintf("%s:%s/%s/%s/%s", SourceKindCES, cluster, cesName, namespace, endpointName) + "/" + podUID)
}

func KVStoreSourceKey(cluster, ipOrPrefix string) SourceKey {
	return SourceKey(fmt.Sprintf("%s:%s/%s", SourceKindKVStore, cluster, ipOrPrefix))
}

type Source struct {
	Key            SourceKey
	Kind           SourceKind
	EndpointKey    EndpointKey
	Aliases        []EndpointKey
	Cluster        string
	Namespace      string
	Name           string
	PodUID         string
	NodeName       string
	EndpointID     string
	IPs            []netip.Addr
	HostIP         netip.Addr
	Identity       identity.NumericIdentity
	EncryptionKey  uint8
	ServiceAccount string
	NamedPorts     types.NamedPortMap
}

func (s Source) endpointKeys() []EndpointKey {
	keys := append([]EndpointKey{}, s.Aliases...)
	if !s.EndpointKey.IsZero() {
		keys = append(keys, s.EndpointKey)
	}
	return dedupeEndpointKeys(keys)
}

func (s Source) priority() int {
	switch s.Kind {
	case SourceKindCEP, SourceKindCES:
		return 0
	case SourceKindKVStore:
		return 1
	default:
		return 2
	}
}

func (s Source) deepCopy() Source {
	out := s
	out.Aliases = append([]EndpointKey{}, s.Aliases...)
	out.IPs = append([]netip.Addr{}, s.IPs...)
	out.NamedPorts = copyNamedPorts(s.NamedPorts)
	return out
}

type Endpoint struct {
	Key            EndpointKey
	Aliases        []EndpointKey
	Cluster        string
	Namespace      string
	Name           string
	IPs            []netip.Addr
	HostIP         netip.Addr
	Identity       identity.NumericIdentity
	EncryptionKey  uint8
	ServiceAccount string
	NamedPorts     types.NamedPortMap
	Sources        map[SourceKey]Source
	Conflicts      []string
}

func (*Endpoint) TableHeader() []string {
	return []string{"Key", "IPs", "Identity", "HostIP", "Sources"}
}

func (e *Endpoint) TableRow() []string {
	ips := make([]string, 0, len(e.IPs))
	for _, ip := range e.IPs {
		ips = append(ips, ip.String())
	}
	return []string{
		e.Key.String(),
		strings.Join(ips, ","),
		e.Identity.StringID(),
		e.HostIP.String(),
		strconv.Itoa(len(e.Sources)),
	}
}

func (e *Endpoint) DeepCopy() *Endpoint {
	if e == nil {
		return nil
	}
	out := *e
	out.Aliases = append([]EndpointKey{}, e.Aliases...)
	out.IPs = append([]netip.Addr{}, e.IPs...)
	out.NamedPorts = copyNamedPorts(e.NamedPorts)
	out.Conflicts = append([]string{}, e.Conflicts...)
	out.Sources = make(map[SourceKey]Source, len(e.Sources))
	for k, src := range e.Sources {
		out.Sources[k] = src.deepCopy()
	}
	return &out
}

var (
	EndpointKeyIndex = statedb.Index[*Endpoint, EndpointKey]{
		Name: "key",
		FromObject: func(ep *Endpoint) index.KeySet {
			return index.NewKeySet(index.String(ep.Key.String()))
		},
		FromKey: func(key EndpointKey) index.Key {
			return index.String(key.String())
		},
		FromString: index.FromString,
		Unique:     true,
	}

	EndpointByKey = EndpointKeyIndex.Query

	EndpointAliasIndex = statedb.Index[*Endpoint, EndpointKey]{
		Name: "alias",
		FromObject: func(ep *Endpoint) index.KeySet {
			keys := make([]index.Key, 0, len(ep.Aliases))
			for _, alias := range ep.Aliases {
				keys = append(keys, index.String(alias.String()))
			}
			return index.NewKeySet(keys...)
		},
		FromKey: func(key EndpointKey) index.Key {
			return index.String(key.String())
		},
		FromString: index.FromString,
		Unique:     true,
	}

	EndpointByAlias = EndpointAliasIndex.Query

	EndpointSourceIndex = statedb.Index[*Endpoint, SourceKey]{
		Name: "source",
		FromObject: func(ep *Endpoint) index.KeySet {
			keys := make([]index.Key, 0, len(ep.Sources))
			for sourceKey := range ep.Sources {
				keys = append(keys, index.String(string(sourceKey)))
			}
			return index.NewKeySet(keys...)
		},
		FromKey: func(key SourceKey) index.Key {
			return index.String(string(key))
		},
		FromString: index.FromString,
		Unique:     true,
	}

	EndpointBySource = EndpointSourceIndex.Query

	EndpointIPIndex = statedb.Index[*Endpoint, netip.Addr]{
		Name: "ip",
		FromObject: func(ep *Endpoint) index.KeySet {
			keys := make([]index.Key, 0, len(ep.IPs))
			for _, ip := range ep.IPs {
				keys = append(keys, index.String(ip.String()))
			}
			return index.NewKeySet(keys...)
		},
		FromKey: func(ip netip.Addr) index.Key {
			return index.String(ip.String())
		},
		FromString: func(key string) (index.Key, error) {
			ip, err := netip.ParseAddr(key)
			if err != nil {
				return nil, err
			}
			return index.String(ip.String()), nil
		},
		Unique: false,
	}

	EndpointByIP = EndpointIPIndex.Query
)

func NewEndpointTable(db *statedb.DB) (statedb.RWTable[*Endpoint], error) {
	return statedb.NewTable(
		db,
		EndpointTableName,
		EndpointKeyIndex,
		EndpointAliasIndex,
		EndpointSourceIndex,
		EndpointIPIndex,
	)
}

type Writer struct {
	table statedb.RWTable[*Endpoint]
}

func NewWriter(table statedb.RWTable[*Endpoint]) *Writer {
	return &Writer{table: table}
}

func (w *Writer) Upsert(txn statedb.WriteTxn, src Source) (*Endpoint, error) {
	if src.Key == "" {
		return nil, fmt.Errorf("source key is required")
	}
	src = src.deepCopy()
	if src.EndpointKey.IsZero() {
		return nil, fmt.Errorf("endpoint key is required for source %q", src.Key)
	}

	if old, _, found := w.table.Get(txn, EndpointBySource(src.Key)); found {
		if _, err := w.removeSourceFromRow(txn, old, src.Key); err != nil {
			return nil, err
		}
	}

	sources := map[SourceKey]Source{src.Key: src}
	candidates := map[string]*Endpoint{}
	for _, key := range src.endpointKeys() {
		if row, _, found := w.table.Get(txn, EndpointByAlias(key)); found {
			candidates[row.Key.String()] = row
		}
	}

	for _, row := range candidates {
		for sourceKey, candidateSource := range row.Sources {
			sources[sourceKey] = candidateSource.deepCopy()
		}
		if _, _, err := w.table.Delete(txn, row); err != nil {
			return nil, err
		}
	}

	ep, err := NewEndpointFromSources(sources)
	if err != nil {
		return nil, err
	}
	if _, _, err := w.table.Insert(txn, ep); err != nil {
		return nil, err
	}
	return ep, nil
}

func (w *Writer) DeleteSource(txn statedb.WriteTxn, key SourceKey) (*Endpoint, bool, error) {
	row, _, found := w.table.Get(txn, EndpointBySource(key))
	if !found {
		return nil, false, nil
	}
	ep, err := w.removeSourceFromRow(txn, row, key)
	if err != nil {
		return nil, false, err
	}
	return ep, true, nil
}

func (w *Writer) removeSourceFromRow(txn statedb.WriteTxn, row *Endpoint, key SourceKey) (*Endpoint, error) {
	remaining := row.DeepCopy()
	delete(remaining.Sources, key)

	if _, _, err := w.table.Delete(txn, row); err != nil {
		return nil, err
	}
	if len(remaining.Sources) == 0 {
		return nil, nil
	}

	ep, err := NewEndpointFromSources(remaining.Sources)
	if err != nil {
		return nil, err
	}
	if _, _, err := w.table.Insert(txn, ep); err != nil {
		return nil, err
	}
	return ep, nil
}

func NewEndpointFromSources(sources map[SourceKey]Source) (*Endpoint, error) {
	if len(sources) == 0 {
		return nil, fmt.Errorf("at least one source is required")
	}

	copiedSources := make(map[SourceKey]Source, len(sources))
	orderedSources := make([]Source, 0, len(sources))
	aliases := []EndpointKey{}
	for key, src := range sources {
		if key == "" {
			return nil, fmt.Errorf("source key is required")
		}
		if src.EndpointKey.IsZero() {
			return nil, fmt.Errorf("endpoint key is required for source %q", key)
		}
		src.Key = key
		src = src.deepCopy()
		copiedSources[key] = src
		orderedSources = append(orderedSources, src)
		aliases = append(aliases, src.endpointKeys()...)
	}
	sortSources(orderedSources)

	aliases = dedupeEndpointKeys(aliases)
	key, err := chooseEndpointKey(aliases)
	if err != nil {
		return nil, err
	}

	ep := &Endpoint{
		Key:     key,
		Aliases: aliases,
		Sources: copiedSources,
	}
	deriveEndpointFields(ep, orderedSources)
	return ep, nil
}

func deriveEndpointFields(ep *Endpoint, sources []Source) {
	if ep.Key.Kind == EndpointKeyKindK8s {
		ep.Cluster = ep.Key.Cluster
		ep.Namespace = ep.Key.Namespace
		ep.Name = ep.Key.Name
	} else {
		ep.Cluster = ep.Key.Cluster
	}

	ipSet := map[netip.Addr]struct{}{}
	var selected *Source
	for i := range sources {
		src := sources[i]
		if selected == nil {
			selected = &src
		}
		for _, ip := range src.IPs {
			if ip.IsValid() {
				ipSet[ip] = struct{}{}
			}
		}
	}
	for ip := range ipSet {
		ep.IPs = append(ep.IPs, ip)
	}
	sort.Slice(ep.IPs, func(i, j int) bool { return ep.IPs[i].Less(ep.IPs[j]) })

	if selected == nil {
		return
	}
	if ep.Cluster == "" {
		ep.Cluster = selected.Cluster
	}
	if ep.Namespace == "" {
		ep.Namespace = selected.Namespace
	}
	if ep.Name == "" {
		ep.Name = selected.Name
	}
	ep.HostIP = selected.HostIP
	ep.Identity = selected.Identity
	ep.EncryptionKey = selected.EncryptionKey
	ep.ServiceAccount = selected.ServiceAccount
	ep.NamedPorts = copyNamedPorts(selected.NamedPorts)
	ep.Conflicts = findConflicts(sources)
}

func SourceFromCEP(cluster string, cep *k8stypes.CiliumEndpoint) (Source, error) {
	if cep == nil {
		return Source{}, fmt.Errorf("nil CiliumEndpoint")
	}
	key := K8sEndpointKey(cluster, cep.Namespace, cep.Name)
	src := Source{
		Key:            CEPSourceKey(cluster, cep.Namespace, cep.Name, string(cep.UID)),
		Kind:           SourceKindCEP,
		EndpointKey:    key,
		Aliases:        []EndpointKey{key},
		Cluster:        cluster,
		Namespace:      cep.Namespace,
		Name:           cep.Name,
		ServiceAccount: cep.ServiceAccount,
	}
	if cep.Identity != nil {
		src.Identity = identity.NumericIdentity(cep.Identity.ID)
	}
	if cep.Networking != nil {
		src.IPs = addressesFromNetworking(cep.Networking)
		src.HostIP = parseAddr(cep.Networking.NodeIP)
	}
	if cep.Encryption != nil {
		src.EncryptionKey = uint8(cep.Encryption.Key)
	}
	src.NamedPorts = namedPortsFromModels(cep.NamedPorts)
	return src, nil
}

func SourcesFromCES(cluster string, ces *ciliumv2alpha1.CiliumEndpointSlice) ([]Source, error) {
	if ces == nil {
		return nil, fmt.Errorf("nil CiliumEndpointSlice")
	}
	sources := make([]Source, 0, len(ces.Endpoints))
	for i := range ces.Endpoints {
		src, err := SourceFromCoreCEP(cluster, ces.Name, ces.Namespace, &ces.Endpoints[i])
		if err != nil {
			return nil, err
		}
		sources = append(sources, src)
	}
	return sources, nil
}

func SourceFromCoreCEP(cluster, cesName, namespace string, ep *ciliumv2alpha1.CoreCiliumEndpoint) (Source, error) {
	if ep == nil {
		return Source{}, fmt.Errorf("nil CoreCiliumEndpoint")
	}
	key := K8sEndpointKey(cluster, namespace, ep.Name)
	src := Source{
		Key:            CESSourceKey(cluster, cesName, namespace, ep.Name, ep.PodUID),
		Kind:           SourceKindCES,
		EndpointKey:    key,
		Aliases:        []EndpointKey{key},
		Cluster:        cluster,
		Namespace:      namespace,
		Name:           ep.Name,
		PodUID:         ep.PodUID,
		Identity:       identity.NumericIdentity(ep.IdentityID),
		EncryptionKey:  uint8(ep.Encryption.Key),
		ServiceAccount: ep.ServiceAccount,
		NamedPorts:     namedPortsFromModels(ep.NamedPorts),
	}
	if ep.Networking != nil {
		src.IPs = addressesFromNetworking(ep.Networking)
		src.HostIP = parseAddr(ep.Networking.NodeIP)
	}
	return src, nil
}

func SourceFromIPIdentityPair(cluster string, pair *identity.IPIdentityPair) (Source, error) {
	if pair == nil {
		return Source{}, fmt.Errorf("nil IPIdentityPair")
	}
	if !pair.IsHost() {
		return Source{}, fmt.Errorf("non-host IPIdentityPair %q is not a managed endpoint", pair.PrefixString())
	}

	ip, err := netip.ParseAddr(pair.PrefixString())
	if err != nil {
		return Source{}, err
	}
	prefix := netip.PrefixFrom(ip, ip.BitLen())
	metadataCluster, nodeName, endpointID, hasGlobal := ParseGlobalEndpointMetadata(pair.Metadata)
	if cluster == "" {
		cluster = metadataCluster
	}
	globalCluster := cluster
	if globalCluster == "" {
		globalCluster = metadataCluster
	}

	aliases := []EndpointKey{IPEndpointKey(cluster, prefix)}
	var key EndpointKey
	if pair.K8sNamespace != "" {
		switch {
		case pair.K8sCEPName != "":
			key = K8sEndpointKey(cluster, pair.K8sNamespace, pair.K8sCEPName)
		case pair.K8sPodName != "":
			key = K8sEndpointKey(cluster, pair.K8sNamespace, pair.K8sPodName)
		}
		if !key.IsZero() {
			aliases = append(aliases, key)
		}
	}
	if hasGlobal {
		aliases = append(aliases, GlobalEndpointKey(globalCluster, nodeName, endpointID))
	}
	if key.IsZero() && hasGlobal {
		key = GlobalEndpointKey(globalCluster, nodeName, endpointID)
	}
	if key.IsZero() {
		key = IPEndpointKey(cluster, prefix)
	}

	name := pair.K8sCEPName
	if name == "" {
		name = pair.K8sPodName
	}
	return Source{
		Key:            KVStoreSourceKey(cluster, pair.PrefixString()),
		Kind:           SourceKindKVStore,
		EndpointKey:    key,
		Aliases:        aliases,
		Cluster:        cluster,
		Namespace:      pair.K8sNamespace,
		Name:           name,
		NodeName:       nodeName,
		EndpointID:     endpointID,
		IPs:            []netip.Addr{ip},
		HostIP:         parseAddr(pair.HostIP.String()),
		Identity:       pair.ID,
		EncryptionKey:  pair.Key,
		ServiceAccount: pair.K8sServiceAccount,
		NamedPorts:     namedPortsFromIdentity(pair.NamedPorts),
	}, nil
}

func ParseGlobalEndpointMetadata(metadata string) (cluster, nodeName, endpointID string, ok bool) {
	parts := strings.Split(metadata, ":")
	if len(parts) != 4 || parts[0] != id.CiliumGlobalIdPrefix.String() {
		return "", "", "", false
	}
	if parts[1] == "" || parts[2] == "" || parts[3] == "" {
		return "", "", "", false
	}
	return parts[1], parts[2], parts[3], true
}

func chooseEndpointKey(keys []EndpointKey) (EndpointKey, error) {
	if len(keys) == 0 {
		return EndpointKey{}, fmt.Errorf("no endpoint keys available")
	}
	for _, kind := range []EndpointKeyKind{EndpointKeyKindK8s, EndpointKeyKindGlobal, EndpointKeyKindIP} {
		matches := make([]EndpointKey, 0, len(keys))
		for _, key := range keys {
			if key.Kind == kind {
				matches = append(matches, key)
			}
		}
		if len(matches) == 0 {
			continue
		}
		sortEndpointKeys(matches)
		return matches[0], nil
	}
	return EndpointKey{}, fmt.Errorf("no supported endpoint keys available")
}

func dedupeEndpointKeys(keys []EndpointKey) []EndpointKey {
	seen := map[string]EndpointKey{}
	for _, key := range keys {
		if key.IsZero() {
			continue
		}
		seen[key.String()] = key
	}
	out := make([]EndpointKey, 0, len(seen))
	for _, key := range seen {
		out = append(out, key)
	}
	sortEndpointKeys(out)
	return out
}

func sortEndpointKeys(keys []EndpointKey) {
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
}

func sortSources(sources []Source) {
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].priority() != sources[j].priority() {
			return sources[i].priority() < sources[j].priority()
		}
		return string(sources[i].Key) < string(sources[j].Key)
	})
}

func addressesFromNetworking(networking *ciliumv2.EndpointNetworking) []netip.Addr {
	if networking == nil {
		return nil
	}
	var out []netip.Addr
	for _, pair := range networking.Addressing {
		if pair == nil {
			continue
		}
		if ip := parseAddr(pair.IPV4); ip.IsValid() {
			out = append(out, ip)
		}
		if ip := parseAddr(pair.IPV6); ip.IsValid() {
			out = append(out, ip)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func parseAddr(s string) netip.Addr {
	if s == "" || s == "<nil>" {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return ip
}

func namedPortsFromModels(ports models.NamedPorts) types.NamedPortMap {
	if len(ports) == 0 {
		return nil
	}
	out := types.NamedPortMap{}
	for _, port := range ports {
		if port == nil {
			continue
		}
		_ = out.AddPort(port.Name, int(port.Port), port.Protocol)
	}
	return out
}

func namedPortsFromIdentity(ports []identity.NamedPort) types.NamedPortMap {
	if len(ports) == 0 {
		return nil
	}
	out := types.NamedPortMap{}
	for _, port := range ports {
		_ = out.AddPort(port.Name, int(port.Port), port.Protocol)
	}
	return out
}

func copyNamedPorts(in types.NamedPortMap) types.NamedPortMap {
	if len(in) == 0 {
		return nil
	}
	out := make(types.NamedPortMap, len(in))
	maps.Copy(out, in)
	return out
}

func findConflicts(sources []Source) []string {
	var conflicts []string
	conflict := func(field string) {
		if slices.Contains(conflicts, field) {
			return
		}
		conflicts = append(conflicts, field)
	}

	var identitySeen identity.NumericIdentity
	var hostIPSeen netip.Addr
	var serviceAccountSeen string
	for _, src := range sources {
		if src.Identity != 0 {
			if identitySeen != 0 && identitySeen != src.Identity {
				conflict("identity")
			}
			identitySeen = src.Identity
		}
		if src.HostIP.IsValid() {
			if hostIPSeen.IsValid() && hostIPSeen != src.HostIP {
				conflict("host-ip")
			}
			hostIPSeen = src.HostIP
		}
		if src.ServiceAccount != "" {
			if serviceAccountSeen != "" && serviceAccountSeen != src.ServiceAccount {
				conflict("service-account")
			}
			serviceAccountSeen = src.ServiceAccount
		}
	}
	sort.Strings(conflicts)
	return conflicts
}
