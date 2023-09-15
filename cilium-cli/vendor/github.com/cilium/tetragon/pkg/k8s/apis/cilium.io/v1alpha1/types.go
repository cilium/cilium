// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package v1alpha1

import (
	ciliumio "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// PodInfo (PI) is the custom resource that stores pod related information

	// PIPluralName is the plural name of Tetragon Pod Info
	PIPluralName = "podinfo"

	// PIKindDefinition is the Kind name of the Tetragon Pod Info
	PIKindDefinition = "PodInfo"

	// PIName is the full name of the Tetragon Pod Info
	PIName = PIPluralName + "." + ciliumio.GroupName
)

type KProbeSpec struct {
	// Name of the function to apply the kprobe spec to.
	Call string `json:"call"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// Indicates whether to collect return value of the traced function.
	Return bool `json:"return"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	// Indicates whether the traced function is a syscall.
	Syscall bool `json:"syscall"`
	// +kubebuilder:validation:Optional
	// A list of function arguments to include in the trace output.
	Args []KProbeArg `json:"args,omitempty"`
	// +kubebuilder:validation:Optional
	// A return argument to include in the trace output.
	ReturnArg *KProbeArg `json:"returnArg,omitempty"`
	// +kubebuilder:validation:Optional
	// An action to perform on the return argument.
	// Available actions are: Post;TrackSock;UntrackSock
	ReturnArgAction string `json:"returnArgAction,omitempty"`
	// +kubebuilder:validation:Optional
	// Selectors to apply before producing trace output. Selectors are ORed.
	Selectors []KProbeSelector `json:"selectors,omitempty"`
}

type KProbeArg struct {
	// +kubebuilder:validation:Minimum=0
	// Position of the argument.
	Index uint32 `json:"index"`
	// +kubebuilder:validation:Enum=int;uint32;int32;uint64;int64;char_buf;char_iovec;size_t;skb;sock;string;fd;file;filename;path;nop;bpf_attr;perf_event;bpf_map;user_namespace;capability;kiocb;iov_iter;cred;load_info;module;
	// Argument type.
	Type string `json:"type"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// Specifies the position of the corresponding size argument for this argument.
	// This field is used only for char_buf and char_iovec types.
	SizeArgIndex uint32 `json:"sizeArgIndex"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// This field is used only for char_buf and char_iovec types. It indicates
	// that this argument should be read later (when the kretprobe for the
	// symbol is triggered) because it might not be populated when the kprobe
	// is triggered at the entrance of the function. For example, a buffer
	// supplied to read(2) won't have content until kretprobe is triggered.
	ReturnCopy bool `json:"returnCopy"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// Read maximum possible data (currently 327360). This field is only used
	// for char_buff data. When this value is false (default), the bpf program
	// will fetch at most 4096 bytes. In later kernels (>=5.4) tetragon
	// supports fetching up to 327360 bytes if this flag is turned on
	MaxData bool `json:"maxData"`
	// +kubebuilder:validation:Optional
	// Label to output in the JSON
	Label string `json:"label"`
}

type BinarySelector struct {
	// +kubebuilder:validation:Enum=In;NotIn
	// Filter operation.
	Operator string `json:"operator"`
	// Value to compare the argument against.
	Values []string `json:"values"`
}

// KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The
// results of MatchPIDs and MatchArgs are ANDed.
type KProbeSelector struct {
	// +kubebuilder:validation:Optional
	// A list of process ID filters. MatchPIDs are ANDed.
	MatchPIDs []PIDSelector `json:"matchPIDs,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of argument filters. MatchArgs are ANDed.
	MatchArgs []ArgSelector `json:"matchArgs,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of actions to execute when this selector matches
	MatchActions []ActionSelector `json:"matchActions,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of argument filters. MatchArgs are ANDed.
	MatchReturnArgs []ArgSelector `json:"matchReturnArgs,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of binary exec name filters.
	MatchBinaries []BinarySelector `json:"matchBinaries,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of namespaces and IDs
	MatchNamespaces []NamespaceSelector `json:"matchNamespaces,omitempty"`
	// +kubebuilder:validation:Optional
	// IDs for namespace changes
	MatchNamespaceChanges []NamespaceChangesSelector `json:"matchNamespaceChanges,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of capabilities and IDs
	MatchCapabilities []CapabilitiesSelector `json:"matchCapabilities,omitempty"`
	// +kubebuilder:validation:Optional
	// IDs for capabilities changes
	MatchCapabilityChanges []CapabilitiesSelector `json:"matchCapabilityChanges,omitempty"`
}

type NamespaceChangesSelector struct {
	// +kubebuilder:validation:Enum=In;NotIn
	// Namespace selector operator.
	Operator string `json:"operator"`
	// Namespace types (e.g., Mnt, Pid) to match.
	Values []string `json:"values"`
}

type NamespaceSelector struct {
	// +kubebuilder:validation:Enum=Uts;Ipc;Mnt;Pid;PidForChildren;Net;Time;TimeForChildren;Cgroup;User
	// Namespace selector name.
	Namespace string `json:"namespace"`
	// +kubebuilder:validation:Enum=In;NotIn
	// Namespace selector operator.
	Operator string `json:"operator"`
	// Namespace IDs (or host_ns for host namespace) of namespaces to match.
	Values []string `json:"values"`
}

type CapabilitiesSelector struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=Effective;Inheritable;Permitted
	// +kubebuilder:default=Effective
	// Type of capabilities
	Type string `json:"type"`
	// +kubebuilder:validation:Enum=In;NotIn
	// Namespace selector operator.
	Operator string `json:"operator"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// Indicates whether these caps are namespace caps.
	IsNamespaceCapability bool `json:"isNamespaceCapability"`
	// Capabilities to match.
	Values []string `json:"values"`
}

type PIDSelector struct {
	// +kubebuilder:validation:Enum=In;NotIn
	// PID selector operator.
	Operator string `json:"operator"`
	// Process IDs to match.
	Values []uint32 `json:"values"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// Indicates whether PIDs are namespace PIDs.
	IsNamespacePID bool `json:"isNamespacePID"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// Matches any descendant processes of the matching PIDs.
	FollowForks bool `json:"followForks"`
}

type ArgSelector struct {
	// +kubebuilder:validation:Minimum=0
	// Position of the argument to apply fhe filter to.
	Index uint32 `json:"index"`
	// +kubebuilder:validation:Enum=Equal;NotEqual;Prefix;NotPrefix;Postfix;NotPostfix;GreaterThan;LessThan;GT;LT;Mask;SPort;NotSPort;SPortPriv;NotSportPriv;DPort;NotDPort;DPortPriv;NotDPortPriv;SAddr;NotSAddr;DAddr;NotDAddr;Protocol;Family;State;InMap;NotInMap
	// Filter operation.
	Operator string `json:"operator"`
	// Value to compare the argument against.
	Values []string `json:"values"`
}

type ActionSelector struct {
	// +kubebuilder:validation:Enum=Post;FollowFD;UnfollowFD;Sigkill;CopyFD;Override;GetUrl;DnsLookup;NoPost;TrackSock;UntrackSock
	// Action to execute.
	Action string `json:"action"`
	// +kubebuilder:validation:Optional
	// An arg index for the fd for fdInstall action
	ArgFd uint32 `json:"argFd"`
	// +kubebuilder:validation:Optional
	// An arg index for the filename for fdInstall action
	ArgName uint32 `json:"argName"`
	// +kubebuilder:validation:Optional
	// A URL for the getUrl action
	ArgUrl string `json:"argUrl"`
	// +kubebuilder:validation:Optional
	// A FQDN to lookup for the dnsLookup action
	ArgFqdn string `json:"argFqdn"`
	// +kubebuilder:validation:Optional
	// error value for override action
	ArgError int32 `json:"argError"`
	// +kubebuilder:validation:Optional
	// A signal number for signal action
	ArgSig uint32 `json:"argSig"`
	// +kubebuilder:validation:Optional
	// An arg index for the sock for trackSock and untrackSock actions
	ArgSock uint32 `json:"argSock"`
	// +kubebuilder:validation:Optional
	// A time period within which repeated messages will not be posted. Can be specified in seconds (default or with
	// 's' suffix), minutes ('m' suffix) or hours ('h' suffix).
	RateLimit string `json:"rateLimit"`
}

type TracepointSpec struct {
	// Tracepoint subsystem
	Subsystem string `json:"subsystem"`
	// Tracepoint event
	Event string `json:"event"`
	// +kubebuilder:validation:Optional
	// A list of function arguments to include in the trace output.
	Args []KProbeArg `json:"args"`
	// +kubebuilder:validation:Optional
	// Selectors to apply before producing trace output. Selectors are ORed.
	Selectors []KProbeSelector `json:"selectors"`
}

type UProbeSpec struct {
	// Name of the traced binary
	Path string `json:"path"`
	// Name of the traced symbol
	Symbol string `json:"symbol"`
	// +kubebuilder:validation:Optional
	// Selectors to apply before producing trace output. Selectors are ORed.
	Selectors []KProbeSelector `json:"selectors"`
}

type ListSpec struct {
	// Name of the list
	Name string `json:"name"`
	// +kubebuilder:validation:Optional
	// Values of the list
	Values []string `json:"values"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=syscalls;generated_syscalls;generated_ftrace
	// Indicates the type of the list values.
	Type string `json:"type,omitempty"`
	// +kubebuilder:validation:Optional
	// Pattern for 'generated' lists.
	Pattern *string `json:"pattern,omitempty"`
}

type PodInfoSpec struct {
	// Host networking requested for this pod. Use the host's network namespace.
	// If this option is set, the ports that will be used must be specified.
	HostNetwork bool `json:"hostNetwork,omitempty"`
}

type PodInfoStatus struct {
	// IP address allocated to the pod. Routable at least within the cluster.
	// Empty if not yet allocated.
	PodIP string `json:"podIP,omitempty"`

	// List of Ip addresses allocated to the pod. 0th entry must be same as PodIP.
	PodIPs []PodIP `json:"podIPs,omitempty"`
}

type PodIP struct {
	// IP is an IP address (IPv4 or IPv6) assigned to the pod
	IP string `json:"IP,omitempty"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="podinfo",path="podinfo",scope="Namespaced",shortName={}

// PodInfo is the Scheme for the Podinfo API
type PodInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PodInfoSpec   `json:"spec,omitempty"`
	Status PodInfoStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PodInfoList contains a list of Podinfo
type PodInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PodInfo `json:"items"`
}
