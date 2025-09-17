// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package logfields defines common logging fields which are used across packages
package logfields

const (
	// Annotations are any annotations for Pods
	Annotations = "annotations"

	// LogSubsys is the field denoting the subsystem when logging
	LogSubsys = "subsys"

	// Version is a field for a generic version number
	Version = "version"

	// NewVersion is a field for a new version number
	NewVersion = "newVersion"

	// OldVersion is a field for a old version number
	OldVersion = "oldVersion"

	// Stacktrace is a field for a stacktrace
	Stacktrace = "stacktrace"

	// Changes is a generic field for any relevant changes
	Changes = "changes"

	// Signal is the field to print os signals on exit etc.
	Signal = "signal"

	// Node is a host machine in the cluster, running cilium
	Node = "node"

	// NodeID is the node-scoped ID of the node as allocated by the agent
	NodeID = "nodeID"

	// NodeName is a human readable name for the node
	NodeName = "nodeName"

	// Endpoint is the endpoint name (e.g. wireguard)
	Endpoint = "endpoint"

	// EndpointID is the numeric endpoint identifier
	EndpointID = "endpointID"

	// EndpointAddressing is the endpoint addressing
	EndpointAddressing = "addressing"

	// EndpointAddressing defines whether to build an endpoint synchronously or not
	EndpointSyncBuild = "sync-build"

	// EndpointState is the current endpoint state
	EndpointState = "endpointState"

	// Error is the Go error
	Error = "error"

	// EventUUID is an event unique identifier
	EventUUID = "eventID"

	// CNIAttachmentID uniquely identifies an endpoint
	CNIAttachmentID = "cniAttachmentID"

	// ContainerID is the container identifier
	ContainerID = "containerID"

	// ContainerInterface is the name of the interface in the container namespace
	ContainerInterface = "containerInterface"

	// IdentityLabels are the labels relevant for the security identity
	IdentityLabels = "identityLabels"

	// InfoLabels are the labels relevant for the security identity
	InfoLabels = "infoLabels"

	// Labels are any label, they may not be relevant to the security identity.
	Labels = "labels"

	// Label is a singular label, where relevant
	Label = "label"

	// ConflictingLabels is the set of labels that conflict
	// with an existing label set.
	ConflictingLabels = "conflictingLabels"

	// SourceFilter is the label or node information source
	SourceFilter = "sourceFilter"

	// Controller is the name of the controller to log it.
	Controller = "controller"

	// Identity is the identifier of a security identity
	Identity = "identity"

	// ConflictingIdentity is the identifier of a security identity that conflicts
	// with 'Identity'
	ConflictingIdentity = "conflictingIdentity"

	// Ingress is the identifier of an ingress object
	Ingress = "ingress"

	// IngressClass is the identifier of an ingress class object
	IngressClass = "ingressClass"

	// IdentityOld is a previously used security identity
	IdentityOld = "old-" + Identity

	IdentityNew = "new-" + Identity

	// PolicyKey is a policy map key
	PolicyKey = "policyKey"

	// PolicyEntry is a policy map value
	PolicyEntry = "policyEntry"

	// PolicyRevision is the revision of the policy in the repository or of
	// the object in question
	PolicyRevision = "policyRevision"

	// PolicyKeysAdded is a set of added policy map keys
	PolicyKeysAdded = "policyKeysAdded"

	// PolicyKeysDeleted is a set of deleted policy map keys
	PolicyKeysDeleted = "policyKeysDeleted"

	// PolicyEntriesOld is a set of old policy map keys and values
	PolicyEntriesOld = "policyEntriesOld"

	// DatapathPolicyRevision is the policy revision currently running in
	// the datapath
	DatapathPolicyRevision = "datapathPolicyRevision"

	// DesiredPolicyRevision is the latest policy revision as evaluated for
	// an endpoint. It is the desired policy revision to be implemented
	// into the datapath.
	DesiredPolicyRevision = "desiredPolicyRevision"

	// PolicyID is the identifier of a L3, L4 or L7 Policy. Ideally the .NumericIdentity
	PolicyID = "policyID"

	// IsDeny is 'true' for a deny rule
	IsDeny = "isDeny"

	// AddedPolicyID is the .NumericIdentity, or set or them
	AddedPolicyID = "policyID.Added"

	// DeletedPolicyID is the .NumericIdentity, or set or them
	DeletedPolicyID = "policyID.Deleted"

	// AddedPolicyDenyID is the .NumericIdentity, or set or them
	AddedPolicyDenyID = "policyID.Deny.Added"

	// DeletedPolicyDenyID is the .NumericIdentity, or set or them
	DeletedPolicyDenyID = "policyID.Deny.Deleted"

	// L3PolicyID is the identifier of a L3 Policy
	L3PolicyID = "policyID.L3"

	// L4PolicyID is the identifier of a L4 Policy
	L4PolicyID = "PolicyID.L4"

	// AuthType is an enum for the type of authentication required, if any.
	AuthType = "AuthType"

	// IsRedirect is a boolean for if the entry is a redirect or not
	IsRedirect = "IsRedirect"

	// DNSName is a FQDN or not fully qualified name intended for DNS lookups
	DNSName = "dnsName"

	// DNSRequestID is the DNS request id used by dns-proxy
	DNSRequestID = "DNSRequestID"

	// MACAddr is a MAC address
	MACAddr = "macAddr"

	// NextHop is an IPV4 or IPv6 address for the next hop
	NextHop = "nextHop"

	// Address is an IPV4, IPv6 or FQDN address
	Address = "address"

	// IPAddr is an IPV4 or IPv6 address
	IPAddr = "ipAddr"

	// IPMask is an IPV4 or IPv6 address mask
	IPMask = "ipMask"

	// IPv4 is an IPv4 address
	IPv4 = "ipv4"

	// IPv6 is an IPv6 address
	IPv6 = "ipv6"

	// BPFCompilationTime is the time elapsed to build a BPF endpoint program
	BPFCompilationTime = "BPFCompilationTime"

	// StartTime is the start time of an event
	StartTime = "startTime"

	// EndTime is the end time of an event
	EndTime = "endTime"

	// Interval is the duration for periodic execution of an operation.
	Interval = "interval"

	// Duration is the duration of a measured operation
	Duration = "duration"

	// V4HealthIP is an address used to contact the cilium-health endpoint
	V4HealthIP = "v4healthIP.IPv4"

	// V6HealthIP is an address used to contact the cilium-health endpoint
	V6HealthIP = "v6healthIP.IPv6"

	// V4IngressIP is an address used to contact the cilium-Ingress endpoint
	V4IngressIP = "v4IngressIP.IPv4"

	// V6IngressIP is an address used to contact the cilium-Ingress endpoint
	V6IngressIP = "v6IngressIP.IPv6"

	// V4CiliumHostIP is an address used for the cilium_host interface.
	V4CiliumHostIP = "v4CiliumHostIP.IPv4"

	// V6CiliumHostIP is an address used for the cilium_host interface.
	V6CiliumHostIP = "v6CiliumHostIP.IPv6"

	// L3n4Addr is a L3 (IP) + L4 (port and protocol) address object.
	L3n4Addr = "l3n4Addr"

	// L3n4AddrID is the allocated ID for a L3n4Addr object
	L3n4AddrID = "l3n4AddrID"

	// Port is a L4 port
	Port = "port"

	// Ports is a list of L4 ports
	Ports = "ports"

	// PortName is a k8s ContainerPort Name
	PortName = "portName"

	// NamedPorts is a set of named ports
	NamedPorts = "namedPorts"

	// Family is the L3 protocol family
	Family = "family"

	// Protocol is the L4 protocol
	Protocol = "protocol"

	// V4Prefix is a IPv4 subnet/CIDR prefix
	V4Prefix = "v4Prefix"

	// V6Prefix is a IPv6 subnet/CIDR prefix
	V6Prefix = "v6Prefix"

	// IPv4CIDRs is a list of IPv4 CIDRs
	IPv4CIDRs = "ipv4CIDRs"

	// IPv6CIDRs is a list of IPv6 CIDRs
	IPv6CIDRs = "ipv6CIDRs"

	// CIDR is a IPv4/IPv6 subnet/CIDR
	CIDR = "cidr"

	// CIDRs is a list of IPv4/IPv6 CIDRs
	CIDRs = "cidrs"

	// OldCIDR is the previous subnet/CIDR
	OldCIDR = "oldCIDR"

	// NewCIDR is the new subnet/CIDR
	NewCIDR = "newCIDR"

	// IPAddrs is a list of IP addrs
	IPAddrs = "ipAddrs"

	// MTU is the maximum transmission unit of one interface
	MTU = "mtu"

	// Interface is an interface id/name on the system
	Interface = "interface"

	// Veth is a veth object or ID
	Veth = "veth"

	// VethPair is a tuple of Veth that are paired
	VethPair = "vethPair"

	// Netkit is a netkit object or ID
	Netkit = "netkit"

	// NetkitPair is a tuple of Netkit that are paired
	NetkitPair = "netkitPair"

	// NetNSName is a name of a network namespace
	NetNSName = "netNSName"

	// HardwareAddr is L2 addr of a network iface
	HardwareAddr = "hardwareAddr"

	// Hash is a hash of something
	Hash = "hash"

	// ServerNames is the list of TLS SNIs
	ServerNames = "serverNames"

	// ServiceName is the orchestration framework name for a service
	ServiceName = "serviceName"

	// ServiceNamespace is the orchestration framework namespace of a service name
	ServiceNamespace = "serviceNamespace"

	// SessionAffinity indicates whether the ClientIP session affinity is enabled
	// for the service
	SessionAffinity = "sessionAffinity"

	// SessionAffinityTimeout is a timeout for the session affinity
	SessionAffinityTimeout = "sessionAffinityTimeout"

	// LoadBalancerAlgorithm is algorithm for backend selection
	LoadBalancerAlgorithm = "LoadBalancerAlgorithm"

	// LoadBalancerSourceRangesPolicy is the LB SVC source ranges policy
	LoadBalancerSourceRangesPolicy = "loadBalancerSourceRangesPolicy"

	// LoadBalancerSourceRanges is the LB SVC source ranges
	LoadBalancerSourceRanges = "loadBalancerSourceRanges"

	// ClusterName is the name of the cluster
	ClusterName = "clusterName"

	// ClusterID is the ID of the cluster
	ClusterID = "clusterID"

	// AddrCluster is a pair of IP address and ClusterID
	AddrCluster = "addrCluster"

	// ServiceID is the orchestration unique ID of a service
	ServiceID = "serviceID"

	// ServiceIP is the IP of the service
	ServiceIP = "serviceIP"

	// ServiceKey is the key of the service in a BPF map
	ServiceKey = "svcKey"

	// ServiceValue is the value of the service in a BPF map
	ServiceValue = "svcVal"

	// ServiceType is the type of the service
	ServiceType = "svcType"

	// ServiceForwardingMode is the mode of the service (SNAT, DSR)
	ServiceForwardingMode = "svcForwardingMode"

	// ServiceHealthCheckNodePort is the port on which we serve health checks
	ServiceHealthCheckNodePort = "svcHealthCheckNodePort"

	// ServiceExtTrafficPolicy is the external traffic policy of the service
	ServiceExtTrafficPolicy = "svcExtTrafficPolicy"

	// ServiceIntTrafficPolicy is the internal traffic policy of the service
	ServiceIntTrafficPolicy = "svcIntTrafficPolicy"

	// BackendIDs is the map of backend IDs (lbmap) indexed by backend address
	BackendIDs = "backendIDs"

	// BackendID is the ID of the backend
	BackendID = "backendID"

	// BackendWeight is a weight of service backend.
	BackendWeight = "backendWeight"

	// Backends is the list of the service backends
	Backends = "backends"

	// BackendName is the name of the backend
	BackendName = "backendName"

	// BackendSlot is the backend slot number in a service BPF map
	BackendSlot = "backendSlot"

	// ProxyName is the name of a proxy (e.g., "Envoy")
	ProxyName = "proxyName"

	// ProxyPort is the port number of an L7 proxy listener.
	ProxyPort = "proxyPort"

	// L7LBProxyPort is the port number of the Envoy listener a L7 LB service redirects traffic to for load balancing.
	L7LBProxyPort = "l7LBProxyPort"

	// L7LBFrontendPorts is the list of frontend ports for load balancing.
	L7LBFrontendPorts = "l7LBFrontendPorts"

	// BackendState is the state of the backend
	BackendState = "backendState"

	// BackendPreferred is the indicator if this backend is preferred if active.
	BackendPreferred = "backendPreferred"

	// CiliumNetworkPolicy is a cilium specific NetworkPolicy
	CiliumNetworkPolicy = "ciliumNetworkPolicy"

	// CiliumNetworkPolicyName is the name of a CiliumNetworkPolicy
	CiliumNetworkPolicyName = "ciliumNetworkPolicyName"

	// CiliumClusterwideNetworkPolicyName is the name of the CiliumClusterWideNetworkPolicy
	CiliumClusterwideNetworkPolicyName = "ciliumClusterwideNetworkPolicyName"

	// BPFClockSource denotes the internal clock source (ktime vs jiffies)
	BPFClockSource = "bpfClockSource"

	// CiliumLocalRedirectPolicyName is the name of a CiliumLocalRedirectPolicy
	CiliumLocalRedirectName = "ciliumLocalRedirectPolicyName"

	// CiliumEgressGatewayPolicyName is the name of a CiliumEgressGatewayPolicy
	CiliumEgressGatewayPolicyName = "ciliumEgressGatewayPolicyName"

	// CiliumClusterwideEnvoyConfigName is the name of a CiliumClusterwideEnvoyConfig
	CiliumClusterwideEnvoyConfigName = "ciliumClusterwideEnvoyConfigName"

	// CiliumEnvoyConfigName is the name of a CiliumEnvoyConfig
	CiliumEnvoyConfigName = "ciliumEnvoyConfigName"

	// Listener is the name of an Envoy Listener defined in CEC or CCEC
	Listener = "listener"

	// L7 parser type
	L7ParserType = "l7-parser-type"

	// Whether original source address can be used or not
	MayUseOriginalSourceAddr = "mayUseOriginalSourceAddr"

	// Name of a resource
	ResourceName = "name"

	// Old value before an operation
	ValueBefore = "before"

	// New value after an operation
	ValueAfter = "after"

	// Number of upserted resources
	ResourcesUpserted = "upserted"

	// Number of deleted resources
	ResourcesDeleted = "deleted"

	// Envoy listeners
	ResourceListeners = "listeners"

	// Envoy routes
	ResourceRoutes = "routes"

	// Envoy clusters
	ResourceClusters = "clusters"

	// Envoy endpoints
	ResourceEndpoints = "endpoints"

	// Envoy secrets
	ResourceSecrets = "secrets"

	// Size of the buffer
	BufferSize = "buffer-size"

	// ListenerPriority is the priority of an Envoy Listener defined in CEC or CCEC
	ListenerPriority = "listenerPriority"

	// BPFMapKey is a key from a BPF map
	BPFMapKey = "bpfMapKey"

	// BPFMapValue is a value from a BPF map
	BPFMapValue = "bpfMapValue"

	// Qdisc is the qdisc name
	Qdisc = "qdisc"

	// Device is the device name
	Device = "device"

	// Devices is the devices name
	Devices = "devices"

	// DirectRoutingDevice is the name of the direct routing device
	DirectRoutingDevice = "directRoutingDevice"

	// DatapathMode is the datapath mode name
	DatapathMode = "datapathMode"

	// DatapathConfiguration is the datapath configuration
	DatapathConfiguration = "datapathConfiguration"

	// Tunnel is the tunnel name
	Tunnel = "tunnel"

	// TunnelPeer is the tunnel peer address
	TunnelPeer = "tunnelPeer"

	// ConflictingTunnelPeer is the address of a tunnel peer which conflicts
	// with TunnelPeer
	ConflictingTunnelPeer = "conflictingTunnelPeer"

	// EndpointFlags is the encoded set of flags for an endpoint
	EndpointFlags = "endpointFlags"

	// ConflictingEndpointFlags is the encoded set of flags that conflicts
	// with 'EndpointFlags'
	ConflictingEndpointFlags = "conflictingEndpointFlags"

	// Type is the address type
	Type = "type"

	// Selector is a selector of any sort: endpoint, CIDR, toFQDNs
	Selector = "Selector"

	// SelectorCacgeVersion is the version of the SelectorCache.
	SelectorCacheVersion = "selectorCacheVersion"

	// EndpointLabelSelector is a selector for Endpoints by label
	EndpointLabelSelector = "EndpointLabelSelector"

	// EndpointSelector is a selector for Endpoints
	EndpointSelector = "EndpointSelector"

	// Path is a filesystem path. It can be a file or directory.
	// Note: pkg/proxy/accesslog points to this variable so be careful when
	// changing the value
	Path = "file-path"

	// Line is a line number within a file
	Line = "line"

	// LinkIndex is a network iface index
	LinkIndex = "linkIndex"

	// Object is used when "%+v" printing Go objects for debug or error handling.
	// It is often paired with logfields.Repr to render the object.
	Object = "obj"

	// Request is a request object received by us, reported in debug or error.
	// It is often paired with logfields.Repr to render the object.
	Request = "req"

	// Params are the parameters of a request, reported in debug or error.
	Params = "params"

	// Response is a response object received by us, reported in debug or error.
	// It is often paired with logfields.Repr to render the object.
	Response = "resp"

	// Resource is a resource
	Resource = "resource"

	// ConflictingResource is a resource that conflicts with 'Resource'
	ConflictingResource = "conflictingResource"

	// Route is a L2 or L3 Linux route
	Route = "route"

	// RetryUUID is an UUID identical for all retries of a set
	RetryUUID = "retryUUID"

	// Rule is an ip rule
	Rule = "rule"

	// Envoy xDS-protocol-specific

	// XDSStreamID is the ID of an xDS request stream.
	XDSStreamID = "xdsStreamID"

	// XDSAckedVersion is the version of an xDS resource acked by Envoy.
	XDSAckedVersion = "xdsAckedVersion"

	// XDSCachedVersion is the version of an xDS resource currently in cache.
	XDSCachedVersion = "xdsCachedVersion"

	// XDSTypeURL is the URL that identifies an xDS resource type.
	XDSTypeURL = "xdsTypeURL"

	// XDSNonce is a nonce sent in xDS requests and responses.
	XDSNonce = "xdsNonce"

	// XDSCanary is a boolean indicating whether a response is a dry run.
	XDSCanary = "xdsCanary"

	// XDSResourceName is the name of an xDS resource.
	XDSResourceName = "xdsResourceName"

	// XDSClientNode is the ID of an XDS client, e.g. an Envoy node.
	XDSClientNode = "xdsClientNode"

	// XDSResource is an xDS resource message.
	XDSResource = "xdsResource"

	// XDSDetail is detail string included in XDS NACKs.
	XDSDetail = "xdsDetail"

	// K8s-specific

	// K8sNodeID is the k8s ID of a K8sNode
	K8sNodeID = "k8sNodeID"

	// K8sPodName is the name of a k8s pod
	K8sPodName = "k8sPodName"

	// K8sSvcName is the name of a K8s service
	K8sSvcName = "k8sSvcName"

	// K8sSvcID is the K8s service name and namespace
	K8sSvcID = "k8sSvcID"

	// K8sSvcType is the k8s service type (e.g. NodePort, Loadbalancer etc.)
	K8sSvcType = "k8sSvcType"

	// K8sEndpointName is the k8s name for a k8s Endpoint (not a cilium Endpoint)
	K8sEndpointName = "k8sEndpointName"

	// K8sNamespace is the namespace something belongs to
	K8sNamespace = "k8sNamespace"

	K8sNamespaceIllegal = "k8sNamespace.illegal"

	// K8sIdentityAnnotation is a k8s non-identifying annotations on k8s objects
	K8sIdentityAnnotation = "k8sIdentityAnnotation"

	// K8sNetworkPolicy is a k8s NetworkPolicy object (not a CiliumNetworkObject, above).
	K8sNetworkPolicy = "k8sNetworkPolicy"

	// K8sNetworkPolicyName is the name of a K8sPolicyObject
	K8sNetworkPolicyName = "k8sNetworkPolicyName"

	// K8sIngress is a k8s Ingress service object
	K8sIngress = "k8sIngress"

	// K8sIngressName is the name of a K8sIngress
	K8sIngressName = "k8sIngressName"

	// K8sAPIVersion is the version of the k8s API an object has
	K8sAPIVersion = "k8sApiVersion"

	// K8sNodeIP is the k8s Node IP (either InternalIP or ExternalIP)
	K8sNodeIP = "k8sNodeIP"

	// K8sUID is the UID of a K8s object
	K8sUID = "k8sUID"

	// Attempt is the attempt number if an operation is attempted multiple times
	Attempt = "attempt"

	// TrafficDirection represents the directionality of traffic with respect
	// to an endpoint.
	TrafficDirection = "trafficDirection"

	// Modification represents a type of state change operation (insert, delete,
	// upsert, etc.).
	Modification = "modification"

	// BPFMapName is the name of a BPF map.
	BPFMapName = "bpfMapName"

	// BPFHeaderHash is the hash of the BPF header.
	BPFHeaderfileHash = "bpfHeaderfileHash"

	// BPFMapPath is the path of a BPF map in the filesystem.
	BPFMapPath = "bpfMapPath"

	// BPFMapFD is the file descriptor for a BPF map.
	BPFMapFD = "bpfMapFileDescriptor"

	// ThreadID is the Envoy thread ID.
	ThreadID = "threadID"

	// Reason is a human readable string describing why an operation was
	// performed
	Reason = "reason"

	// Limit is a numerical limit that has been exceeded
	Limit = "limit"

	// Count is a measure being compared to the Limit
	Count = "count"

	Total = "total"

	// Debug is a boolean value for whether debug is set or not.
	Debug = "debug"

	// PID is an integer value for the process identifier of a process.
	PID = "pid"

	// PIDFile is a string value for the path to a file containing a PID.
	PIDFile = "pidfile"

	// Probe is the name of a status probe.
	Probe = "probe"

	// Key is the identity of the encryption key
	Key = "key"

	// ConflictingKey is the identity of the encryption key which conflicts with
	// Key
	ConflictingKey = "conflictingKey"

	// URL represents a Uniform Resource Locator.
	URL = "url"

	// SysParamName is the name of the kernel parameter (sysctl)
	SysParamName = "sysParamName"

	// SysParamValue is the value of the kernel parameter (sysctl)
	SysParamValue = "sysParamValue"

	// SysParamBaselineValue is the value of the base kernel parameter (sysctl)
	SysParamBaselineValue = "baselineValue"

	// HashSeed is the seed value for the hashing algorithm
	HashSeed = "hashSeed"

	// HelpMessage is the help message corresponding to a log message.
	// This is to make sure we keep separate contexts for logs and help messages.
	HelpMessage = "helpMessage"

	// LRPName is the parsed name of the Local Redirect Policy.
	LRPName = "lrpName"

	// LRPFrontend is the parsed frontend mappings of the Local Redirect Policy.
	LRPFrontends = "lrpFrontends"

	// LRPLocalEndpointSelector is the local endpoint selector of the Local Redirect Policy.
	LRPLocalEndpointSelector = "lrpLocalEndpointSelector"

	// LRPBackendPorts are the parsed backend ports of the Local Redirect Policy.
	LRPBackendPorts = "lrpBackendPorts"

	// LRPType is the type of the Local Redirect Policy.
	LRPType = "lrpType"

	// LRPFrontendType is the parsed frontend type of the Local Redirect Policy.
	LRPFrontendType = "lrpFrontendType"

	// ENPName is the name of the egress nat policy
	ENPName = "enpName"

	// AccelarationMode

	AccelarationMode = "accelarationMode"

	// Mode describes an operations mode
	Mode = "mode"

	// PubKey is the public key
	PubKey = "pubKey"

	// NodeIPv4 is the node IPv4 addr
	NodeIPv4 = "nodeIPv4"

	// NodeIPv6 is the node IPv4 addr
	NodeIPv6 = "nodeIPv6"

	// OldNode refers to the node before the update
	OldNode = "oldNode"

	// NewNode refers to the node after the update
	NewNode = "newNode"

	// AttachedENIs are the ENIs which have been attached to the node
	AttachedENIs = "attachedENIs"

	// ExpectedENIs are the ENIs which are expected to be available
	ExpectedENIs = "expectedENIs"

	// Hint helps nudge the user in the right direction when troubleshooting.
	Hint = "hint"

	// CEPName is the name of the CiliumEndpoint.
	CEPName = "ciliumEndpointName"

	// CEPCount is the count of the CiliumEndpoint.
	CEPCount = "ciliumEndpointCount"

	// CEPUID is the UID of the CiliumEndpoint.
	CEPUID = "ciliumEndpointUID"

	// CIDName is the name of the CiliumIdentity.
	CIDName = "ciliumIdentityName"

	// CESName is the name of the CiliumEndpointSlice.
	CESName = "ciliumEndpointSliceName"

	// WorkQueueQPSLimit is the QPS limit for WorkQueues.
	WorkQueueQPSLimit = "workQueueQPSLimit"

	// WorkQueueBurstLimit is the burst limit for WorkQueues.
	WorkQueueBurstLimit = "workQueueBurstLimit"

	// WorkQueueSyncBackoff is the backoff time used by workqueues before an attempt to retry sync with k8s-apiserver.
	WorkQueueSyncBackOff    = "workQueueSyncBackOff"
	WorkQueueMaxSyncBackOff = "workQueueMaxSyncBackOff"

	// SourceIP is a source IP
	SourceIP = "sourceIP"

	DestinationIP = "destinationIP"

	LocalIP = "localIP"

	RemoteIP = "remoteIP"

	SourceCIDR = "sourceCIDR"

	// DestinationCIDR is a destination CIDR
	DestinationCIDR = "destinationCIDR"

	// EgressIP is the egress IP used in a given egress policy
	EgressIP = "egressIP"

	// GatewayIP is the gateway IP used in a given egress policy
	GatewayIP = "gatewayIP"

	// Number of Backends failed while restoration.
	RestoredBackends = "restoredBackends"

	// Number of Backends failed while restoration.
	FailedBackends = "failedBackends"

	// SkippedBackends is the number of Backends that were skipped during restore
	// as duplicates.
	SkippedBackends = "skippedBackends"

	// OrphanBackends is the number Backends that are not associated with any services.
	OrphanBackends = "orphanBackends"

	// Number of Services failed while restoration.
	RestoredSVCs = "restoredServices"

	// Number of Services failed while restoration.
	FailedSVCs = "failedServices"

	// Chain is an Iptables chain
	Chain = "chain"

	// IPSec SPI
	SPI = "spi"

	// IPSec old SPI
	OldSPI = "oldSPI"

	// CGroupId is the numerical cgroup id
	CGroupID = "cgroupID"

	// Expected is an expected value
	Expected = "expected"

	// ConfigSource is a configuration source (for process options, e.g. agent)
	ConfigSource = "configSource"

	// ConfigKey is a single key in a configuration source
	ConfigKey = "configKey"

	// ConfigAnnotation is an annotation on a node
	ConfigAnnotation = "configAnnotation"

	// User identifies a given user
	User = "user"

	// CIDRGroupRef is a references to a CiliumCIDRGroup object.
	CIDRGroupRef = "cidrGroupRef"

	// Workers represents the number of workers.
	Workers = "workers"

	// Event identifies the type of an event.
	Event = "event"

	// Prefix identifies a given prefix.
	Prefix = "prefix"

	// Value identifies a generic value (e.g., of a key/value pair).
	Value = "value"

	// State is the state of an individual component (apiserver, kvstore etc)
	State = "state"

	// EtcdQPSLimit is the QPS limit for an etcd client.
	EtcdQPSLimit = "etcdQPSLimit"

	// LeaseID identifies a KVStore lease
	LeaseID = "leaseID"

	// EventType identifies the type of KVStore events
	EventType = "eventType"

	// Entries specifies the number of KVStore entries
	Entries = "entries"
	// Action is the summarized action from a reconciliation.
	Action = "action"

	// EtcdClusterID is the ID of the etcd cluster
	EtcdClusterID = "etcdClusterID"

	// NetnsCookie is the Linux kernel netns cookie.
	NetnsCookie = "netnsCookie"

	// Source identifies a source value
	Source = "source"

	// Target identifies a target value
	Target = "target"

	// Minimum specifies a minimum allowed value
	Minimum = "minimum"

	// Maximum specifies a maximum allowed value
	Maximum = "maximum"

	// Size identifies the size of a list
	Size = "size"

	// Directory identifies a directory
	Directory = "directory"
	// PacketsDropped are the number of packets dropped
	PacketsDropped = "packetsDropped"

	// From represents the source
	From = "from"

	// To represents the destination
	To = "to"

	// GsoMaxSize is the GSO Max Size
	GsoMaxSize = "gso_max_size"

	// GroMaxSize is the GRO Max Size
	GroMaxSize = "gro_max_size"

	// Flag is the program flag
	Flag = "flag"

	// NewRules refers to the new rules after the update
	NewRules = "newRules"

	// L7Parser is the L7 parser used for L7 network traffic
	L7Parser = "l7parser"

	// ProxyType is the proxy type
	ProxyType = "proxyType"

	// RetryDelay the delay used for a retry
	RetryDelay = "retryDelay"

	// LastLevel is the last level for the health status
	LastLevel = "lastLevel"

	// ReporterID the reporter's ID
	ReporterID = "reporter-id"

	// Status is the status
	Status = "status"

	// DeletedRules is the length of rules deleted
	DeletedRules = "deletedRules"

	// Deleted is the length of structs deleted
	Deleted = "deleted"

	Upserted = "upserted"

	Updated = "updated"

	New = "new"

	Old = "old"

	Name = "name"

	ProxyRedirect = "proxyRedirect"

	Message = "message"

	Zone = "zone"

	Got = "got"

	Want = "want"

	Removed = "removed"

	NetNSDir = "netns-dir"

	Index = "index"

	RemoteNodeID = "remoteNodeID"

	RemoteNodeIP = "remoteNodeIP"

	NodeIDs = "NodeIDs"

	LocalIdentity = "localIdentity"

	RemoteIdentity = "remoteIdentity"

	Expiration = "expiration"

	GCTime = "gcTime"

	Backoff = "backOff"

	SortedAt = "sortedAt"

	SNI = "SNI"

	SNIID = "SNIID"

	URISan = "URISan"

	SPIFEEID = "SPIFEEID"

	TrustDomain = "TrustDomain"

	LenSVIDs = "lenSVIDs"

	LenBundles = "lenBundles"

	EnvoyID = "ID"

	EnvoyCluster = "cluster"

	UserAgent = "userAgent"

	Neighbor = "neighbor"

	AllocCIDR = "allocCIDR"

	Feature = "feature"

	Enabled = "enabled"

	QuietMode = "quietMode"

	NodeIP = "nodeIP"

	Actual = "actual"

	ExpectedValue = "expectedValue"

	ExpectedSource = "expectedSource"

	NewIP = "newIP"

	OldIP = "oldIP"

	AddedCIDRs = "addedCIDRs"

	RemovedCIDRs = "removedCIDRs"

	ID = "ID"

	Link = "link"

	Hook = "hook"

	DNSRedirect = "dnsRedirect"

	EnvoyRedirect = "envoyRedirect"

	Slot = "slot"

	First = "first"

	Second = "second"

	Backend = "backend"

	FrontendID = "frontendID"

	ListenerID = "listenerID"

	Frontend = "frontend"

	HostPort = "hostPort"

	NodePortMin = "nodePortMin"

	NodePortMax = "nodePortMax"

	Active = "active"

	Previous = "previous"

	HostIP = "hostIP"

	PoolSpec = "poolSpec"

	PoolOldSpec = "poolOldSpec"

	PoolNewSpec = "poolNewSpec"

	PoolName = "poolName"

	MaxRetries = "maxRetries"

	Retries = "retries"

	Gateway = "gateway"

	Kind = "kind"

	RequiredGVK = "requiredGVK"

	OptionalGVK = "optionalGVK"

	ClusterConfig = "clusterConfig"

	NodeConfig = "nodeConfig"

	Server = "server"

	PoolName1 = "poolName1"

	PoolName2 = "poolName2"

	PoolRange1 = "poolRange1"

	PoolRange2 = "poolRange2"

	Min = "min"

	Max = "max"

	IdentitiesToDelete = "identitiesToDelete"

	CRDIdentityCount = "crdIdentityCount"

	KVStoreIdentityCount = "kvstoreIdentityCount"

	OnlyInCRDCount = "onlyInCrdCount"

	OnlyInKVStoreCount = "onlyInKvstoreCount"

	OnlyInCRDSample = "onlyInCrdSample"

	OnlyInKVStoreSample = "onlyInKvstoreSample"

	Service = "service"

	ConfigFile = "configFile"

	Registrations = "registrations"

	HTTPRoute = "httpRoute"

	Secret = "secret"

	Nodes = "nodes"

	Endpoints = "endpoints"

	Shared = "shared"

	Taint = "taint"

	Pod = "pod"

	Allocated = "allocated"

	IPv4Limit = "ipv4Limit"

	AvailableOnENI = "availableOnENI"

	VSwitchID = "vSwitchID"

	AvailableAddresses = "availableAddresses"

	NumAddresses = "numAddresses"

	NumVPCs = "numVPCs"

	NumVSwitches = "numVSwitches"

	NumSecurityGroups = "numSecurityGroups"

	NumInstances = "numInstances"

	ExcessIPs = "excessIPs"

	FreeOnENICount = "freeOnENICount"

	InstanceID = "instanceID"

	VPCID = "vpcID"

	Tags = "tags"

	SecurityGroupIDs = "securityGroupIDs"

	ToAllocate = "toAllocate"

	SubscriptionID = "subscriptionID"

	IPv4MaskSize = "ipv4MaskSize"

	IPv6MaskSize = "ipv6MaskSize"

	TargetNode = "targetNode"

	SourcePool = "sourcePool"

	Owner = "owner"

	UUID = "uuid"

	Available = "available"

	Required = "required"

	VPCCIDR = "vpcCIDR"

	Capacity = "capacity"

	Used = "used"

	ToRelease = "toRelease"

	WaitingForPoolMaintenance = "waitingForPoolMaintenance"

	ResyncNeeded = "resyncNeeded"

	RemainingInterfaces = "remainingInterfaces"

	SelectedInterface = "selectedInterface"

	SelectedPoolID = "selectedPoolID"

	MaxIPsToAllocate = "maxIPsToAllocate"

	AvailableForAllocation = "availableForAllocation"

	EmptyInterfaceSlots = "emptyInterfaceSlots"

	NeededIPs = "neededIPs"

	Releasing = "releasing"

	Excess = "excess"

	ReleasingAddresses = "releasingAddresses"

	IPsToAllocate = "ipsToAllocate"

	PoolSize = "poolSize"

	ENI = "eni"

	PrefixCount = "prefixCount"

	LenEIPS = "lenEIPS"

	EIP = "eip"

	AssociationID = "associationID"

	NumInterfaces = "numInterfaces"

	NumSubnets = "numSubnets"

	NumRouteTables = "numRouteTables"

	NeedIndex = "needIndex"

	AddressLimit = "addressLimit"

	SubnetID = "subnetID"

	Addresses = "addresses"

	IsPrefixDelegated = "isPrefixDelegated"

	AttachmentID = "attachmentID"

	FirstInterfaceIndex = "firstInterfaceIndex"

	AdaptersLimit = "adaptersLimit"

	PreAllocate = "preAllocate"

	InstanceType = "instanceType"

	NumVirtualNetworks = "numVirtualNetworks"

	CanAllocatePodCIDRs = "canAllocatePodCIDRs"

	Group = "group"

	Method = "method"

	Client = "client"

	PanicMessage = "panicMessage"

	Reasons = "reasons"

	Config = "config"

	MetricConfig = "metricConfig"

	TLS = "tls"

	FlowLogName = "flowLogName"

	Options = "options"

	RelatedMetric = "related-metric"

	Filters = "filters"

	MaxFlows = "maxFlows"

	EventQueueSize = "eventQueueSize"

	NumberOfFlows = "numberOfFlows"

	Whitelist = "whiltelist"

	Blacklist = "blackList"

	Took = "took"

	NumberOfAgentEvents = "numberOfAgentEvents"

	NumberOfDebugEvents = "numberOfDebugEvents"

	DatapathIdentity = "datapathIdentity"

	UserspaceIdentity = "userspaceIdentity"

	Context = "context"

	NumEvents = "numEvents"

	CPU = "cpu"

	RuleID = "ruleID"

	FilePath = "filePath"

	Peer = "peer"

	ConnectionTimeout = "connectionTimeout"

	ChangeNotification = "changeNotification"

	NextTryIn = "nextTryIn"

	Operation = "operation"

	KeyPairSN = "keyPairSN"

	AnnotationsOld = "annotationsOld"

	LabelsNew = "labelsNew"

	File = "file"

	Timeout = "timeout"

	EtcdDataDir = "etcdDataDir"

	EtcdClusterName = "etcdClusterName"

	EtcdInitialClusterToken = "etcdInitialClusterToken"

	EtcdListenClientUrl = "loopbackEndpoint"

	EtcdBinary = "etcdBinaryLocation"

	EtcdFlags = "etcdCmd"

	EtcdExitCode = "etcdExitCode"

	EtcdClientConfig = "etcdClientConfig"

	EtcdUsername = "etcdUsername"

	EtcdRoleName = "etcdRoleName"

	EtcdPermission = "etcdPermission"

	EtcdRangeStart = "etcdRangeStart"

	EtcdRangeEnd = "etcdRangeEnd"

	K8sExportName = "K8sExportName"

	ReliablyMissing = "reliablyMissing"

	KVStoreBackendConfigurationSuffix = "kvStoreBackendConfiguration.Suffix"

	KVStoreBackendConfigurationTyp = "kvStoreBackendConfiguration.Typ"

	KVStoreBackendConfigurationBasePath = "kvStoreBackendConfiguration.BasePath"

	ReadFromKVStore = "readFromKVStore"

	TTL = "ttl"

	ConfigPath = "configPath"

	KeepAliveHeartbeat = "keepAliveHeartbeat"

	KeepAliveTimeout = "keepAliveTimeout"

	RateLimit = "rateLimit"

	MaxInflight = "maxInflight"

	ListLimit = "listLimit"

	TimeWindow = "timeWindow"

	Entry = "entry"

	LastEventReceived = "lastEventReceived"

	PodIP = "podIP"

	PodIPs = "podIPs"

	NewPodIP = "newPodIP"

	NewPodIPs = "newPodIPs"

	NewHostIP = "newHostIP"

	OldPodIP = "oldPodIP"

	OldPodIPs = "oldPodIPs"

	OldHostIP = "oldHostIP"

	OldLabels = "oldLabels"

	OldAnnotations = "oldAnnotations"

	NewLabels = "newLabels"

	NewAnnotations = "newAnnotations"

	OldService = "oldService"

	OldEndpoints = "oldEndpoints"

	LenEndpoints = "lenEndpoints"

	LenBackends = "lenBackends"

	CRDs = "CRDs"

	PodCIDRs = "podCIDRs"

	LenIPs = "lenIPs"

	Alias = "alias"

	GlobalConfiguration = "globalConfiguration"

	Annotation = "annotation"

	LPM = "LPM"

	IngressDeleted = "ingressDeleted"

	EgressDeleted = "egressDeleted"

	IngressAlive = "ingressAlive"

	EgressAlive = "egressAlive"

	CTMapIPVersion = "ctMapIPVersion"

	ExpectedPrevInterval = "expectedPrevInterval"

	ActualPrevInterval = "actualPrevInterval"

	NewInterval = "newInterval"

	DeleteRatio = "deleteRatio"

	AdjustedDeleteRatio = "adjustedDeleteRatio"

	Interrupted = "interrupted"

	Errors = "errors"

	IPSet = "ipset"

	Cmd = "cmd"

	Prog = "prog"

	Table = "table"

	OptionalParameter = "optionalParameter"

	Param = "param"

	Module = "module"

	NeedFor = "needFor"

	ProgType = "progType"

	Helper = "helper"

	Routes = "routes"

	RevertError = "revertError"

	BootTime = "bootTime"

	BootstrapTime = "bootstrapTime"

	Socket = "socket"

	Filter = "filter"

	Success = "success"

	Failed = "failed"

	BPFFSEndpointLinksDir = "bpffsEndpointLinksDir"

	BPFFSEndpointDir = "bpffsEndpointDir"

	CompilerPID = "compilerPID"

	Output = "output"

	RssBytes = "rssBytes"

	BPFSPath = "bpffsPath"

	ProgName = "progName"

	Range = "range"

	Pin = "pin"

	Priority = "priority"

	Args = "args"

	Candidates = "candidates"

	Location = "location"

	Skipped = "skipped"

	AliveEntries = "aliveEntries"

	Scope = "scope"

	NewLocally = "newLocally"

	Released = "released"

	DNSRulesV2 = "dnsRulesV2"

	BPFHeaderfileHashOld = "old-" + "bpfHeaderfileHash"

	DumpedPolicyMap = "dumpedPolicyMap"

	DumpedDiffs = "dumpedDiffs"

	NewDirectory = "newDirectory"

	TmpDirectory = "tmpDirectory"

	Code = "code"

	EndpointStateFrom = "endpointStateFrom"

	EndpointStateTo = "endpointStateTo"

	BandwidthLimit = "bandwidthLimit"

	PolicyRevisionNext = "policyRevisionNext"

	PolicyRevisionRepo = "policyRevisionRepo"

	PolicyChanged = "policyChanged"

	CEPUIDOld = "old-" + CEPUID

	HubbleCLIVersion = "hubble-cli-version"

	HubbleRelayVersion = "hubble-relay-version"

	HubbleServerVersion = "hubble-server-version"

	Handler = "handler"

	NodeOwner = "nodeOwner"

	LenStaleNodes = "lenStaleNodes"

	StaleNodes = "staleNodes"

	SyncInterval = "syncInterval"

	BootID = "bootID"

	LeaseDuration = "leaseDuration"

	RenewDeadline = "renewDeadline"

	RetryPeriod = "retryPeriod"

	Resources = "resources"

	LastModifiedVersion = "lastModifiedVersion"

	ReturningResources = "returningResources"

	RequestedResources = "requestedResources"

	ResponseNonce = "responseNonce"

	ResourceWatcherVersion = "resourceWatcherVersion"

	WaitVersion = "waitVersion"

	CurrentVersion = "currentVersion"

	PendingCompletions = "pendingCompletions"

	Root = "root"

	LenConfigPairs = "lenConfigPairs"

	Exists = "exists"

	MulticastAddr = "multicastAddr"

	IPMask4 = "ipMask4"

	IPMask6 = "ipMask6"

	IPRules = "ipRules"

	Rules = "rules"

	SecID = "secID"

	WrittenBytes = "writtenBytes"

	TotalBytes = "totalBytes"

	Destination = "destination"

	LenEntries = "lenEntries"

	FQDNSelector = "fqdnSelector"

	MatchName = "matchName"

	LenPrefixes = "lenPrefixes"

	LookupIPAddrs = "lookupIPAddrs"

	MatchPattern = "matchPattern"

	BPFFSRoot = "bpffsRoot"

	Section = "section"

	Instruction = "instruction"

	Reference = "reference"

	MapRenames = "mapRenames"

	Constants = "constants"

	Remaining = "remaining"

	Resolved = "resolved"

	Scanned = "scanned"

	KeySize = "keySize"

	Subnets = "subnets"

	Ratio = "ratio"

	OldName = "oldName"

	NewName = "newName"

	ValueSize = "valueSize"

	MaxEntries = "maxEntries"

	Flags = "flags"

	ExitCode = "exitCode"

	NetLink = "netLink"

	NetConf = "netConf"

	Result = "result"

	NetNamespace = "netNamespace"

	DockerHostPath = "dockerHostPath"

	ImageID = "imageID"

	NumBufferedEvents = "numBufferedEvents"

	EventHandlingDuration = "eventHandlingDuration"

	EventEnqueueWaitTime = "eventEnqueueWaitTime"

	CalculatedInterval = "calculatedInterval"

	MaxAllowedInterval = "maxAllowedInterval"

	EventConsumeOffQueueWaitTime = "eventConsumeOffQueueWaitTime"

	CachedSource = "cachedSource"

	Info = "info"

	OperatorID = "operatorID"

	NewLeader = "newLeader"

	KVStore = "kvstore"

	LabelSelectorFlagOption = "label-selector"

	RemoveCiliumNodeTaintsFlagOption = "remove-cilium-node-taints"

	SetCiliumNodeTaintsFlagOption = "set-cilium-node-taints"

	SetCiliumIsUpConditionFlagOption = "set-cilium-is-up-condition"

	TimeSinceRestart = "timeSinceRestart"

	TimeSincePodStarted = "timeSincePodStarted"

	DNSRules = "dnsRules"

	PortProtocol = "portProtocol"

	Option = "option"

	RunDirectory = "runDirectory"

	LibDirectory = "libDirectory"

	BPFDirectory = "BPFDirectory"

	StateDirectory = "StateDirectory"

	Restored = "restored"

	Detected = "detected"

	NodeLabels = "nodeLabels"

	UID = "UID"

	ProviderID = "providerID"

	EndpointLXCID = "endpointLXCID"

	Regenerated = "regenerated"

	Primary = "primary"

	RTT = "rtt"

	URI = "uri"

	Goroutine = "goroutine"

	Matcher = "matcher"

	ParentResource = "parentResource"

	Fraction = "fraction"

	Rate = "rate"

	KPRConfiguration = "kprConfiguration"
)
