# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [flow/flow.proto](#flow_flow-proto)
    - [AgentEvent](#flow-AgentEvent)
    - [AgentEventUnknown](#flow-AgentEventUnknown)
    - [CiliumEventType](#flow-CiliumEventType)
    - [DNS](#flow-DNS)
    - [DebugEvent](#flow-DebugEvent)
    - [Endpoint](#flow-Endpoint)
    - [EndpointRegenNotification](#flow-EndpointRegenNotification)
    - [EndpointUpdateNotification](#flow-EndpointUpdateNotification)
    - [Ethernet](#flow-Ethernet)
    - [EventTypeFilter](#flow-EventTypeFilter)
    - [Flow](#flow-Flow)
    - [FlowFilter](#flow-FlowFilter)
    - [HTTP](#flow-HTTP)
    - [HTTPHeader](#flow-HTTPHeader)
    - [ICMPv4](#flow-ICMPv4)
    - [ICMPv6](#flow-ICMPv6)
    - [IP](#flow-IP)
    - [IPCacheNotification](#flow-IPCacheNotification)
    - [Kafka](#flow-Kafka)
    - [Layer4](#flow-Layer4)
    - [Layer7](#flow-Layer7)
    - [LostEvent](#flow-LostEvent)
    - [NetworkInterface](#flow-NetworkInterface)
    - [PolicyUpdateNotification](#flow-PolicyUpdateNotification)
    - [SCTP](#flow-SCTP)
    - [Service](#flow-Service)
    - [ServiceDeleteNotification](#flow-ServiceDeleteNotification)
    - [ServiceUpsertNotification](#flow-ServiceUpsertNotification)
    - [ServiceUpsertNotificationAddr](#flow-ServiceUpsertNotificationAddr)
    - [TCP](#flow-TCP)
    - [TCPFlags](#flow-TCPFlags)
    - [TimeNotification](#flow-TimeNotification)
    - [TraceContext](#flow-TraceContext)
    - [TraceParent](#flow-TraceParent)
    - [UDP](#flow-UDP)
    - [Workload](#flow-Workload)
  
    - [AgentEventType](#flow-AgentEventType)
    - [DebugCapturePoint](#flow-DebugCapturePoint)
    - [DebugEventType](#flow-DebugEventType)
    - [DropReason](#flow-DropReason)
    - [EventType](#flow-EventType)
    - [FlowType](#flow-FlowType)
    - [IPVersion](#flow-IPVersion)
    - [L7FlowType](#flow-L7FlowType)
    - [LostEventSource](#flow-LostEventSource)
    - [SocketTranslationPoint](#flow-SocketTranslationPoint)
    - [TraceObservationPoint](#flow-TraceObservationPoint)
    - [TrafficDirection](#flow-TrafficDirection)
    - [Verdict](#flow-Verdict)
  
- [Scalar Value Types](#scalar-value-types)



<a name="flow_flow-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## flow/flow.proto



<a name="flow-AgentEvent"></a>

### AgentEvent



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [AgentEventType](#flow-AgentEventType) |  |  |
| unknown | [AgentEventUnknown](#flow-AgentEventUnknown) |  |  |
| agent_start | [TimeNotification](#flow-TimeNotification) |  |  |
| policy_update | [PolicyUpdateNotification](#flow-PolicyUpdateNotification) |  | used for POLICY_UPDATED and POLICY_DELETED |
| endpoint_regenerate | [EndpointRegenNotification](#flow-EndpointRegenNotification) |  | used for ENDPOINT_REGENERATE_SUCCESS and ENDPOINT_REGENERATE_FAILURE |
| endpoint_update | [EndpointUpdateNotification](#flow-EndpointUpdateNotification) |  | used for ENDPOINT_CREATED and ENDPOINT_DELETED |
| ipcache_update | [IPCacheNotification](#flow-IPCacheNotification) |  | used for IPCACHE_UPSERTED and IPCACHE_DELETED |
| service_upsert | [ServiceUpsertNotification](#flow-ServiceUpsertNotification) |  |  |
| service_delete | [ServiceDeleteNotification](#flow-ServiceDeleteNotification) |  |  |






<a name="flow-AgentEventUnknown"></a>

### AgentEventUnknown



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [string](#string) |  |  |
| notification | [string](#string) |  |  |






<a name="flow-CiliumEventType"></a>

### CiliumEventType
CiliumEventType from which the flow originated


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [int32](#int32) |  | type of event the flow originated from, i.e. github.com/cilium/cilium/pkg/monitor/api.MessageType* |
| sub_type | [int32](#int32) |  | sub_type may indicate more details depending on type, e.g. - github.com/cilium/cilium/pkg/monitor/api.Trace* - github.com/cilium/cilium/pkg/monitor/api.Drop* - github.com/cilium/cilium/pkg/monitor/api.DbgCapture* |






<a name="flow-DNS"></a>

### DNS
DNS flow. This is basically directly mapped from Cilium&#39;s LogRecordDNS:
    https://github.com/cilium/cilium/blob/04f3889d627774f79e56d14ddbc165b3169e2d01/pkg/proxy/accesslog/record.go#L264


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| query | [string](#string) |  | DNS name that&#39;s being looked up: e.g. &#34;isovalent.com.&#34; |
| ips | [string](#string) | repeated | List of IP addresses in the DNS response. |
| ttl | [uint32](#uint32) |  | TTL in the DNS response. |
| cnames | [string](#string) | repeated | List of CNames in the DNS response. |
| observation_source | [string](#string) |  | Corresponds to DNSDataSource defined in: https://github.com/cilium/cilium/blob/04f3889d627774f79e56d14ddbc165b3169e2d01/pkg/proxy/accesslog/record.go#L253 |
| rcode | [uint32](#uint32) |  | Return code of the DNS request defined in: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6 |
| qtypes | [string](#string) | repeated | String representation of qtypes defined in: https://tools.ietf.org/html/rfc1035#section-3.2.3 |
| rrtypes | [string](#string) | repeated | String representation of rrtypes defined in: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4 |






<a name="flow-DebugEvent"></a>

### DebugEvent



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [DebugEventType](#flow-DebugEventType) |  |  |
| source | [Endpoint](#flow-Endpoint) |  |  |
| hash | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  |  |
| arg1 | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  |  |
| arg2 | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  |  |
| arg3 | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  |  |
| message | [string](#string) |  |  |
| cpu | [google.protobuf.Int32Value](#google-protobuf-Int32Value) |  |  |






<a name="flow-Endpoint"></a>

### Endpoint



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| ID | [uint32](#uint32) |  |  |
| identity | [uint32](#uint32) |  |  |
| namespace | [string](#string) |  |  |
| labels | [string](#string) | repeated | labels in `foo=bar` format. |
| pod_name | [string](#string) |  |  |
| workloads | [Workload](#flow-Workload) | repeated |  |






<a name="flow-EndpointRegenNotification"></a>

### EndpointRegenNotification



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint64](#uint64) |  |  |
| labels | [string](#string) | repeated |  |
| error | [string](#string) |  |  |






<a name="flow-EndpointUpdateNotification"></a>

### EndpointUpdateNotification



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint64](#uint64) |  |  |
| labels | [string](#string) | repeated |  |
| error | [string](#string) |  |  |
| pod_name | [string](#string) |  |  |
| namespace | [string](#string) |  |  |






<a name="flow-Ethernet"></a>

### Ethernet



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source | [string](#string) |  |  |
| destination | [string](#string) |  |  |






<a name="flow-EventTypeFilter"></a>

### EventTypeFilter
EventTypeFilter is a filter describing a particular event type


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [int32](#int32) |  | type is the primary flow type as defined by: github.com/cilium/cilium/pkg/monitor/api.MessageType* |
| match_sub_type | [bool](#bool) |  | match_sub_type is set to true when matching on the sub_type should be done. This flag is required as 0 is a valid sub_type. |
| sub_type | [int32](#int32) |  | sub_type is the secondary type, e.g. - github.com/cilium/cilium/pkg/monitor/api.Trace* |






<a name="flow-Flow"></a>

### Flow



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |
| uuid | [string](#string) |  | uuid is a universally unique identifier for this flow. |
| verdict | [Verdict](#flow-Verdict) |  |  |
| drop_reason | [uint32](#uint32) |  | **Deprecated.** only applicable to Verdict = DROPPED. deprecated in favor of drop_reason_desc. |
| ethernet | [Ethernet](#flow-Ethernet) |  | l2 |
| IP | [IP](#flow-IP) |  | l3 |
| l4 | [Layer4](#flow-Layer4) |  | l4 |
| source | [Endpoint](#flow-Endpoint) |  |  |
| destination | [Endpoint](#flow-Endpoint) |  |  |
| Type | [FlowType](#flow-FlowType) |  |  |
| node_name | [string](#string) |  | NodeName is the name of the node from which this Flow was captured. |
| source_names | [string](#string) | repeated | all names the source IP can have. |
| destination_names | [string](#string) | repeated | all names the destination IP can have. |
| l7 | [Layer7](#flow-Layer7) |  | L7 information. This field is set if and only if FlowType is L7. |
| reply | [bool](#bool) |  | **Deprecated.** Deprecated. This suffers from false negatives due to protobuf not being able to distinguish between the value being false or it being absent. Please use is_reply instead. |
| event_type | [CiliumEventType](#flow-CiliumEventType) |  | EventType of the originating Cilium event |
| source_service | [Service](#flow-Service) |  | source_service contains the service name of the source |
| destination_service | [Service](#flow-Service) |  | destination_service contains the service name of the destination |
| traffic_direction | [TrafficDirection](#flow-TrafficDirection) |  | traffic_direction of the connection, e.g. ingress or egress |
| policy_match_type | [uint32](#uint32) |  | policy_match_type is only applicable to the cilium event type PolicyVerdict https://github.com/cilium/cilium/blob/e831859b5cc336c6d964a6d35bbd34d1840e21b9/pkg/monitor/datapath_policy.go#L50 |
| trace_observation_point | [TraceObservationPoint](#flow-TraceObservationPoint) |  | Only applicable to cilium trace notifications, blank for other types. |
| drop_reason_desc | [DropReason](#flow-DropReason) |  | only applicable to Verdict = DROPPED. |
| is_reply | [google.protobuf.BoolValue](#google-protobuf-BoolValue) |  | is_reply indicates that this was a packet (L4) or message (L7) in the reply direction. May be absent (in which case it is unknown whether it is a reply or not). |
| debug_capture_point | [DebugCapturePoint](#flow-DebugCapturePoint) |  | Only applicable to cilium debug capture events, blank for other types |
| interface | [NetworkInterface](#flow-NetworkInterface) |  | interface is the network interface on which this flow was observed |
| proxy_port | [uint32](#uint32) |  | proxy_port indicates the port of the proxy to which the flow was forwarded |
| trace_context | [TraceContext](#flow-TraceContext) |  | trace_context contains information about a trace related to the flow, if any. |
| sock_xlate_point | [SocketTranslationPoint](#flow-SocketTranslationPoint) |  | sock_xlate_point is the socket translation point. Only applicable to TraceSock notifications, blank for other types |
| socket_cookie | [uint64](#uint64) |  | socket_cookie is the Linux kernel socket cookie for this flow. Only applicable to TraceSock notifications, zero for other types |
| cgroup_id | [uint64](#uint64) |  | cgroup_id of the process which emitted this event. Only applicable to TraceSock notifications, zero for other types |
| Summary | [string](#string) |  | **Deprecated.** This is a temporary workaround to support summary field for pb.Flow without duplicating logic from the old parser. This field will be removed once we fully migrate to the new parser. |






<a name="flow-FlowFilter"></a>

### FlowFilter
FlowFilter represent an individual flow filter. All fields are optional. If
multiple fields are set, then all fields must match for the filter to match.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uuid | [string](#string) | repeated | uuid filters by a list of flow uuids. |
| source_ip | [string](#string) | repeated | source_ip filters by a list of source ips. Each of the source ips can be specified as an exact match (e.g. &#34;1.1.1.1&#34;) or as a CIDR range (e.g. &#34;1.1.1.0/24&#34;). |
| source_pod | [string](#string) | repeated | source_pod filters by a list of source pod name prefixes, optionally within a given namespace (e.g. &#34;xwing&#34;, &#34;kube-system/coredns-&#34;). The pod name can be omitted to only filter by namespace (e.g. &#34;kube-system/&#34;) |
| source_fqdn | [string](#string) | repeated | source_fqdn filters by a list of source fully qualified domain names |
| source_label | [string](#string) | repeated | source_labels filters on a list of source label selectors. Selectors support the full Kubernetes label selector syntax. |
| source_service | [string](#string) | repeated | source_service filters on a list of source service names. This field supports the same syntax as the source_pod field. |
| source_workload | [Workload](#flow-Workload) | repeated | source_workload filters by a list of source workload. |
| destination_ip | [string](#string) | repeated | destination_ip filters by a list of destination ips. Each of the destination ips can be specified as an exact match (e.g. &#34;1.1.1.1&#34;) or as a CIDR range (e.g. &#34;1.1.1.0/24&#34;). |
| destination_pod | [string](#string) | repeated | destination_pod filters by a list of destination pod names |
| destination_fqdn | [string](#string) | repeated | destination_fqdn filters by a list of destination fully qualified domain names |
| destination_label | [string](#string) | repeated | destination_label filters on a list of destination label selectors |
| destination_service | [string](#string) | repeated | destination_service filters on a list of destination service names |
| destination_workload | [Workload](#flow-Workload) | repeated | destination_workload filters by a list of destination workload. |
| traffic_direction | [TrafficDirection](#flow-TrafficDirection) | repeated | traffic_direction filters flow by direction of the connection, e.g. ingress or egress. |
| verdict | [Verdict](#flow-Verdict) | repeated | only return Flows that were classified with a particular verdict. |
| event_type | [EventTypeFilter](#flow-EventTypeFilter) | repeated | event_type is the list of event types to filter on |
| http_status_code | [string](#string) | repeated | http_status_code is a list of string prefixes (e.g. &#34;4&#43;&#34;, &#34;404&#34;, &#34;5&#43;&#34;) to filter on the HTTP status code |
| protocol | [string](#string) | repeated | protocol filters flows by L4 or L7 protocol, e.g. (e.g. &#34;tcp&#34;, &#34;http&#34;) |
| source_port | [string](#string) | repeated | source_port filters flows by L4 source port |
| destination_port | [string](#string) | repeated | destination_port filters flows by L4 destination port |
| reply | [bool](#bool) | repeated | reply filters flows based on the direction of the flow. |
| dns_query | [string](#string) | repeated | dns_query filters L7 DNS flows by query patterns (RE2 regex), e.g. &#39;kube.*local&#39;. |
| source_identity | [uint32](#uint32) | repeated | source_identity filters by the security identity of the source endpoint. |
| destination_identity | [uint32](#uint32) | repeated | destination_identity filters by the security identity of the destination endpoint. |
| http_method | [string](#string) | repeated | GET, POST, PUT, etc. methods. This type of field is well suited for an enum but every single existing place is using a string already. |
| http_path | [string](#string) | repeated | http_path is a list of regular expressions to filter on the HTTP path. |
| tcp_flags | [TCPFlags](#flow-TCPFlags) | repeated | tcp_flags filters flows based on TCP header flags |
| node_name | [string](#string) | repeated | node_name is a list of patterns to filter on the node name, e.g. &#34;k8s*&#34;, &#34;test-cluster/*.domain.com&#34;, &#34;cluster-name/&#34; etc. |
| ip_version | [IPVersion](#flow-IPVersion) | repeated | filter based on IP version (ipv4 or ipv6) |
| trace_id | [string](#string) | repeated | trace_id filters flows by trace ID |






<a name="flow-HTTP"></a>

### HTTP
L7 information for HTTP flows. It corresponds to Cilium&#39;s accesslog.LogRecordHTTP type.
  https://github.com/cilium/cilium/blob/728c79e427438ab6f8d9375b62fccd6fed4ace3a/pkg/proxy/accesslog/record.go#L206


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| code | [uint32](#uint32) |  |  |
| method | [string](#string) |  |  |
| url | [string](#string) |  |  |
| protocol | [string](#string) |  |  |
| headers | [HTTPHeader](#flow-HTTPHeader) | repeated |  |






<a name="flow-HTTPHeader"></a>

### HTTPHeader



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="flow-ICMPv4"></a>

### ICMPv4



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [uint32](#uint32) |  |  |
| code | [uint32](#uint32) |  |  |






<a name="flow-ICMPv6"></a>

### ICMPv6



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [uint32](#uint32) |  |  |
| code | [uint32](#uint32) |  |  |






<a name="flow-IP"></a>

### IP



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source | [string](#string) |  |  |
| destination | [string](#string) |  |  |
| ipVersion | [IPVersion](#flow-IPVersion) |  |  |
| encrypted | [bool](#bool) |  | This field indicates whether the TraceReasonEncryptMask is set or not. https://github.com/cilium/cilium/blob/ba0ed147bd5bb342f67b1794c2ad13c6e99d5236/pkg/monitor/datapath_trace.go#L27 |






<a name="flow-IPCacheNotification"></a>

### IPCacheNotification



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cidr | [string](#string) |  |  |
| identity | [uint32](#uint32) |  |  |
| old_identity | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  |  |
| host_ip | [string](#string) |  |  |
| old_host_ip | [string](#string) |  |  |
| encrypt_key | [uint32](#uint32) |  |  |
| namespace | [string](#string) |  |  |
| pod_name | [string](#string) |  |  |






<a name="flow-Kafka"></a>

### Kafka
L7 information for Kafka flows. It corresponds to Cilium&#39;s accesslog.LogRecordKafka type.
  https://github.com/cilium/cilium/blob/728c79e427438ab6f8d9375b62fccd6fed4ace3a/pkg/proxy/accesslog/record.go#L229


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| error_code | [int32](#int32) |  |  |
| api_version | [int32](#int32) |  |  |
| api_key | [string](#string) |  |  |
| correlation_id | [int32](#int32) |  |  |
| topic | [string](#string) |  |  |






<a name="flow-Layer4"></a>

### Layer4



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| TCP | [TCP](#flow-TCP) |  |  |
| UDP | [UDP](#flow-UDP) |  |  |
| ICMPv4 | [ICMPv4](#flow-ICMPv4) |  | ICMP is technically not L4, but mutually exclusive with the above |
| ICMPv6 | [ICMPv6](#flow-ICMPv6) |  |  |
| SCTP | [SCTP](#flow-SCTP) |  |  |






<a name="flow-Layer7"></a>

### Layer7
Message for L7 flow, which roughly corresponds to Cilium&#39;s accesslog LogRecord:
  https://github.com/cilium/cilium/blob/728c79e427438ab6f8d9375b62fccd6fed4ace3a/pkg/proxy/accesslog/record.go#L141


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [L7FlowType](#flow-L7FlowType) |  |  |
| latency_ns | [uint64](#uint64) |  | Latency of the response |
| dns | [DNS](#flow-DNS) |  |  |
| http | [HTTP](#flow-HTTP) |  |  |
| kafka | [Kafka](#flow-Kafka) |  |  |






<a name="flow-LostEvent"></a>

### LostEvent
LostEvent is a message which notifies consumers about a loss of events
that happened before the events were captured by Hubble.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source | [LostEventSource](#flow-LostEventSource) |  | source is the location where events got lost. |
| num_events_lost | [uint64](#uint64) |  | num_events_lost is the number of events that haven been lost at source. |
| cpu | [google.protobuf.Int32Value](#google-protobuf-Int32Value) |  | cpu on which the event was lost if the source of lost events is PERF_EVENT_RING_BUFFER. |






<a name="flow-NetworkInterface"></a>

### NetworkInterface



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| index | [uint32](#uint32) |  |  |
| name | [string](#string) |  |  |






<a name="flow-PolicyUpdateNotification"></a>

### PolicyUpdateNotification



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| labels | [string](#string) | repeated |  |
| revision | [uint64](#uint64) |  |  |
| rule_count | [int64](#int64) |  |  |






<a name="flow-SCTP"></a>

### SCTP



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source_port | [uint32](#uint32) |  |  |
| destination_port | [uint32](#uint32) |  |  |






<a name="flow-Service"></a>

### Service



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| namespace | [string](#string) |  |  |






<a name="flow-ServiceDeleteNotification"></a>

### ServiceDeleteNotification



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint32](#uint32) |  |  |






<a name="flow-ServiceUpsertNotification"></a>

### ServiceUpsertNotification



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint32](#uint32) |  |  |
| frontend_address | [ServiceUpsertNotificationAddr](#flow-ServiceUpsertNotificationAddr) |  |  |
| backend_addresses | [ServiceUpsertNotificationAddr](#flow-ServiceUpsertNotificationAddr) | repeated |  |
| type | [string](#string) |  |  |
| traffic_policy | [string](#string) |  | **Deprecated.**  |
| name | [string](#string) |  |  |
| namespace | [string](#string) |  |  |
| ext_traffic_policy | [string](#string) |  |  |
| int_traffic_policy | [string](#string) |  |  |






<a name="flow-ServiceUpsertNotificationAddr"></a>

### ServiceUpsertNotificationAddr



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| ip | [string](#string) |  |  |
| port | [uint32](#uint32) |  |  |






<a name="flow-TCP"></a>

### TCP



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source_port | [uint32](#uint32) |  |  |
| destination_port | [uint32](#uint32) |  |  |
| flags | [TCPFlags](#flow-TCPFlags) |  |  |






<a name="flow-TCPFlags"></a>

### TCPFlags



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| FIN | [bool](#bool) |  |  |
| SYN | [bool](#bool) |  |  |
| RST | [bool](#bool) |  |  |
| PSH | [bool](#bool) |  |  |
| ACK | [bool](#bool) |  |  |
| URG | [bool](#bool) |  |  |
| ECE | [bool](#bool) |  |  |
| CWR | [bool](#bool) |  |  |
| NS | [bool](#bool) |  |  |






<a name="flow-TimeNotification"></a>

### TimeNotification



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |






<a name="flow-TraceContext"></a>

### TraceContext
TraceContext contains trace context propagation data, ie information about a
distributed trace.
For more information about trace context, check the W3C Trace Context
specification: https://www.w3.org/TR/trace-context/


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| parent | [TraceParent](#flow-TraceParent) |  | parent identifies the incoming request in a tracing system. |






<a name="flow-TraceParent"></a>

### TraceParent
TraceParent identifies the incoming request in a tracing system.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| trace_id | [string](#string) |  | trace_id is a unique value that identifies a trace. It is a byte array represented as a hex string. |






<a name="flow-UDP"></a>

### UDP



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source_port | [uint32](#uint32) |  |  |
| destination_port | [uint32](#uint32) |  |  |






<a name="flow-Workload"></a>

### Workload



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| kind | [string](#string) |  |  |





 


<a name="flow-AgentEventType"></a>

### AgentEventType
AgentEventType is the type of agent event. These values are shared with type
AgentNotification in pkg/monitor/api/types.go

| Name | Number | Description |
| ---- | ------ | ----------- |
| AGENT_EVENT_UNKNOWN | 0 |  |
| AGENT_STARTED | 2 |  |
| POLICY_UPDATED | 3 |  |
| POLICY_DELETED | 4 |  |
| ENDPOINT_REGENERATE_SUCCESS | 5 |  |
| ENDPOINT_REGENERATE_FAILURE | 6 |  |
| ENDPOINT_CREATED | 7 |  |
| ENDPOINT_DELETED | 8 |  |
| IPCACHE_UPSERTED | 9 |  |
| IPCACHE_DELETED | 10 |  |
| SERVICE_UPSERTED | 11 |  |
| SERVICE_DELETED | 12 |  |



<a name="flow-DebugCapturePoint"></a>

### DebugCapturePoint
These values are shared with pkg/monitor/api/datapath_debug.go and bpf/lib/dbg.h.

| Name | Number | Description |
| ---- | ------ | ----------- |
| DBG_CAPTURE_POINT_UNKNOWN | 0 |  |
| DBG_CAPTURE_DELIVERY | 4 |  |
| DBG_CAPTURE_FROM_LB | 5 |  |
| DBG_CAPTURE_AFTER_V46 | 6 |  |
| DBG_CAPTURE_AFTER_V64 | 7 |  |
| DBG_CAPTURE_PROXY_PRE | 8 |  |
| DBG_CAPTURE_PROXY_POST | 9 |  |
| DBG_CAPTURE_SNAT_PRE | 10 |  |
| DBG_CAPTURE_SNAT_POST | 11 |  |



<a name="flow-DebugEventType"></a>

### DebugEventType
These values are shared with pkg/monitor/api/datapath_debug.go and bpf/lib/dbg.h.

| Name | Number | Description |
| ---- | ------ | ----------- |
| DBG_EVENT_UNKNOWN | 0 |  |
| DBG_GENERIC | 1 |  |
| DBG_LOCAL_DELIVERY | 2 |  |
| DBG_ENCAP | 3 |  |
| DBG_LXC_FOUND | 4 |  |
| DBG_POLICY_DENIED | 5 |  |
| DBG_CT_LOOKUP | 6 |  |
| DBG_CT_LOOKUP_REV | 7 |  |
| DBG_CT_MATCH | 8 |  |
| DBG_CT_CREATED | 9 |  |
| DBG_CT_CREATED2 | 10 |  |
| DBG_ICMP6_HANDLE | 11 |  |
| DBG_ICMP6_REQUEST | 12 |  |
| DBG_ICMP6_NS | 13 |  |
| DBG_ICMP6_TIME_EXCEEDED | 14 |  |
| DBG_CT_VERDICT | 15 |  |
| DBG_DECAP | 16 |  |
| DBG_PORT_MAP | 17 |  |
| DBG_ERROR_RET | 18 |  |
| DBG_TO_HOST | 19 |  |
| DBG_TO_STACK | 20 |  |
| DBG_PKT_HASH | 21 |  |
| DBG_LB6_LOOKUP_FRONTEND | 22 |  |
| DBG_LB6_LOOKUP_FRONTEND_FAIL | 23 |  |
| DBG_LB6_LOOKUP_BACKEND_SLOT | 24 |  |
| DBG_LB6_LOOKUP_BACKEND_SLOT_SUCCESS | 25 |  |
| DBG_LB6_LOOKUP_BACKEND_SLOT_V2_FAIL | 26 |  |
| DBG_LB6_LOOKUP_BACKEND_FAIL | 27 |  |
| DBG_LB6_REVERSE_NAT_LOOKUP | 28 |  |
| DBG_LB6_REVERSE_NAT | 29 |  |
| DBG_LB4_LOOKUP_FRONTEND | 30 |  |
| DBG_LB4_LOOKUP_FRONTEND_FAIL | 31 |  |
| DBG_LB4_LOOKUP_BACKEND_SLOT | 32 |  |
| DBG_LB4_LOOKUP_BACKEND_SLOT_SUCCESS | 33 |  |
| DBG_LB4_LOOKUP_BACKEND_SLOT_V2_FAIL | 34 |  |
| DBG_LB4_LOOKUP_BACKEND_FAIL | 35 |  |
| DBG_LB4_REVERSE_NAT_LOOKUP | 36 |  |
| DBG_LB4_REVERSE_NAT | 37 |  |
| DBG_LB4_LOOPBACK_SNAT | 38 |  |
| DBG_LB4_LOOPBACK_SNAT_REV | 39 |  |
| DBG_CT_LOOKUP4 | 40 |  |
| DBG_RR_BACKEND_SLOT_SEL | 41 |  |
| DBG_REV_PROXY_LOOKUP | 42 |  |
| DBG_REV_PROXY_FOUND | 43 |  |
| DBG_REV_PROXY_UPDATE | 44 |  |
| DBG_L4_POLICY | 45 |  |
| DBG_NETDEV_IN_CLUSTER | 46 |  |
| DBG_NETDEV_ENCAP4 | 47 |  |
| DBG_CT_LOOKUP4_1 | 48 |  |
| DBG_CT_LOOKUP4_2 | 49 |  |
| DBG_CT_CREATED4 | 50 |  |
| DBG_CT_LOOKUP6_1 | 51 |  |
| DBG_CT_LOOKUP6_2 | 52 |  |
| DBG_CT_CREATED6 | 53 |  |
| DBG_SKIP_PROXY | 54 |  |
| DBG_L4_CREATE | 55 |  |
| DBG_IP_ID_MAP_FAILED4 | 56 |  |
| DBG_IP_ID_MAP_FAILED6 | 57 |  |
| DBG_IP_ID_MAP_SUCCEED4 | 58 |  |
| DBG_IP_ID_MAP_SUCCEED6 | 59 |  |
| DBG_LB_STALE_CT | 60 |  |
| DBG_INHERIT_IDENTITY | 61 |  |
| DBG_SK_LOOKUP4 | 62 |  |
| DBG_SK_LOOKUP6 | 63 |  |
| DBG_SK_ASSIGN | 64 |  |



<a name="flow-DropReason"></a>

### DropReason
These values are shared with pkg/monitor/api/drop.go and bpf/lib/common.h.
Note that non-drop reasons (i.e. values less than api.DropMin) are not used
here.

| Name | Number | Description |
| ---- | ------ | ----------- |
| DROP_REASON_UNKNOWN | 0 | non-drop reasons |
| INVALID_SOURCE_MAC | 130 | drop reasons |
| INVALID_DESTINATION_MAC | 131 |  |
| INVALID_SOURCE_IP | 132 |  |
| POLICY_DENIED | 133 |  |
| INVALID_PACKET_DROPPED | 134 |  |
| CT_TRUNCATED_OR_INVALID_HEADER | 135 |  |
| CT_MISSING_TCP_ACK_FLAG | 136 |  |
| CT_UNKNOWN_L4_PROTOCOL | 137 |  |
| CT_CANNOT_CREATE_ENTRY_FROM_PACKET | 138 |  |
| UNSUPPORTED_L3_PROTOCOL | 139 |  |
| MISSED_TAIL_CALL | 140 |  |
| ERROR_WRITING_TO_PACKET | 141 |  |
| UNKNOWN_L4_PROTOCOL | 142 |  |
| UNKNOWN_ICMPV4_CODE | 143 |  |
| UNKNOWN_ICMPV4_TYPE | 144 |  |
| UNKNOWN_ICMPV6_CODE | 145 |  |
| UNKNOWN_ICMPV6_TYPE | 146 |  |
| ERROR_RETRIEVING_TUNNEL_KEY | 147 |  |
| ERROR_RETRIEVING_TUNNEL_OPTIONS | 148 |  |
| INVALID_GENEVE_OPTION | 149 |  |
| UNKNOWN_L3_TARGET_ADDRESS | 150 |  |
| STALE_OR_UNROUTABLE_IP | 151 |  |
| NO_MATCHING_LOCAL_CONTAINER_FOUND | 152 |  |
| ERROR_WHILE_CORRECTING_L3_CHECKSUM | 153 |  |
| ERROR_WHILE_CORRECTING_L4_CHECKSUM | 154 |  |
| CT_MAP_INSERTION_FAILED | 155 |  |
| INVALID_IPV6_EXTENSION_HEADER | 156 |  |
| IP_FRAGMENTATION_NOT_SUPPORTED | 157 |  |
| SERVICE_BACKEND_NOT_FOUND | 158 |  |
| NO_TUNNEL_OR_ENCAPSULATION_ENDPOINT | 160 |  |
| FAILED_TO_INSERT_INTO_PROXYMAP | 161 |  |
| REACHED_EDT_RATE_LIMITING_DROP_HORIZON | 162 |  |
| UNKNOWN_CONNECTION_TRACKING_STATE | 163 |  |
| LOCAL_HOST_IS_UNREACHABLE | 164 |  |
| NO_CONFIGURATION_AVAILABLE_TO_PERFORM_POLICY_DECISION | 165 |  |
| UNSUPPORTED_L2_PROTOCOL | 166 |  |
| NO_MAPPING_FOR_NAT_MASQUERADE | 167 |  |
| UNSUPPORTED_PROTOCOL_FOR_NAT_MASQUERADE | 168 |  |
| FIB_LOOKUP_FAILED | 169 |  |
| ENCAPSULATION_TRAFFIC_IS_PROHIBITED | 170 |  |
| INVALID_IDENTITY | 171 |  |
| UNKNOWN_SENDER | 172 |  |
| NAT_NOT_NEEDED | 173 |  |
| IS_A_CLUSTERIP | 174 |  |
| FIRST_LOGICAL_DATAGRAM_FRAGMENT_NOT_FOUND | 175 |  |
| FORBIDDEN_ICMPV6_MESSAGE | 176 |  |
| DENIED_BY_LB_SRC_RANGE_CHECK | 177 |  |
| SOCKET_LOOKUP_FAILED | 178 |  |
| SOCKET_ASSIGN_FAILED | 179 |  |
| PROXY_REDIRECTION_NOT_SUPPORTED_FOR_PROTOCOL | 180 |  |
| POLICY_DENY | 181 |  |
| VLAN_FILTERED | 182 |  |
| INVALID_VNI | 183 |  |
| INVALID_TC_BUFFER | 184 |  |
| NO_SID | 185 |  |
| MISSING_SRV6_STATE | 186 |  |
| NAT46 | 187 |  |
| NAT64 | 188 |  |
| AUTH_REQUIRED | 189 |  |
| CT_NO_MAP_FOUND | 190 |  |
| SNAT_NO_MAP_FOUND | 191 |  |
| INVALID_CLUSTER_ID | 192 |  |
| UNSUPPORTED_PROTOCOL_FOR_DSR_ENCAP | 193 |  |
| NO_EGRESS_GATEWAY | 194 |  |



<a name="flow-EventType"></a>

### EventType
EventType are constants are based on the ones from &lt;linux/perf_event.h&gt;.

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN | 0 |  |
| EventSample | 9 | EventSample is equivalent to PERF_RECORD_SAMPLE. |
| RecordLost | 2 | RecordLost is equivalent to PERF_RECORD_LOST. |



<a name="flow-FlowType"></a>

### FlowType


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN_TYPE | 0 |  |
| L3_L4 | 1 | not sure about the underscore here, but `L34` also reads strange |
| L7 | 2 |  |
| SOCK | 3 |  |



<a name="flow-IPVersion"></a>

### IPVersion


| Name | Number | Description |
| ---- | ------ | ----------- |
| IP_NOT_USED | 0 |  |
| IPv4 | 1 |  |
| IPv6 | 2 |  |



<a name="flow-L7FlowType"></a>

### L7FlowType
This enum corresponds to Cilium&#39;s L7 accesslog FlowType:
  https://github.com/cilium/cilium/blob/728c79e427438ab6f8d9375b62fccd6fed4ace3a/pkg/proxy/accesslog/record.go#L26

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN_L7_TYPE | 0 |  |
| REQUEST | 1 |  |
| RESPONSE | 2 |  |
| SAMPLE | 3 |  |



<a name="flow-LostEventSource"></a>

### LostEventSource


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN_LOST_EVENT_SOURCE | 0 |  |
| PERF_EVENT_RING_BUFFER | 1 | PERF_EVENT_RING_BUFFER indicates that events were dropped in the BPF perf event ring buffer, indicating that userspace agent did not keep up with the events produced by the datapath. |
| OBSERVER_EVENTS_QUEUE | 2 | OBSERVER_EVENTS_QUEUE indicates that events were dropped because the Hubble events queue was full, indicating that the Hubble observer did not keep up. |
| HUBBLE_RING_BUFFER | 3 | HUBBLE_RING_BUFFER indicates that the event was dropped because it could not be read from Hubble&#39;s ring buffer in time before being overwritten. |



<a name="flow-SocketTranslationPoint"></a>

### SocketTranslationPoint
This mirrors enum xlate_point in bpf/lib/trace_sock.h

| Name | Number | Description |
| ---- | ------ | ----------- |
| SOCK_XLATE_POINT_UNKNOWN | 0 |  |
| SOCK_XLATE_POINT_PRE_DIRECTION_FWD | 1 | Pre service translation |
| SOCK_XLATE_POINT_POST_DIRECTION_FWD | 2 | Post service translation |
| SOCK_XLATE_POINT_PRE_DIRECTION_REV | 3 | Pre reverse service translation |
| SOCK_XLATE_POINT_POST_DIRECTION_REV | 4 | Post reverse service translation |



<a name="flow-TraceObservationPoint"></a>

### TraceObservationPoint


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN_POINT | 0 | Cilium treats 0 as TO_LXC, but its&#39;s something we should work to remove. This is intentionally set as unknown, so proto API can guarantee the observation point is always going to be present on trace events. |
| TO_PROXY | 1 | TO_PROXY indicates network packets are transmitted towards the l7 proxy. |
| TO_HOST | 2 | TO_HOST indicates network packets are transmitted towards the host namespace. |
| TO_STACK | 3 | TO_STACK indicates network packets are transmitted towards the Linux kernel network stack on host machine. |
| TO_OVERLAY | 4 | TO_OVERLAY indicates network packets are transmitted towards the tunnel device. |
| TO_ENDPOINT | 101 | TO_ENDPOINT indicates network packets are transmitted towards endpoints (containers). |
| FROM_ENDPOINT | 5 | FROM_ENDPOINT indicates network packets were received from endpoints (containers). |
| FROM_PROXY | 6 | FROM_PROXY indicates network packets were received from the l7 proxy. |
| FROM_HOST | 7 | FROM_HOST indicates network packets were received from the host namespace. |
| FROM_STACK | 8 | FROM_STACK indicates network packets were received from the Linux kernel network stack on host machine. |
| FROM_OVERLAY | 9 | FROM_OVERLAY indicates network packets were received from the tunnel device. |
| FROM_NETWORK | 10 | FROM_NETWORK indicates network packets were received from native devices. |
| TO_NETWORK | 11 | TO_NETWORK indicates network packets are transmitted towards native devices. |



<a name="flow-TrafficDirection"></a>

### TrafficDirection


| Name | Number | Description |
| ---- | ------ | ----------- |
| TRAFFIC_DIRECTION_UNKNOWN | 0 |  |
| INGRESS | 1 |  |
| EGRESS | 2 |  |



<a name="flow-Verdict"></a>

### Verdict


| Name | Number | Description |
| ---- | ------ | ----------- |
| VERDICT_UNKNOWN | 0 | UNKNOWN is used if there is no verdict for this flow event |
| FORWARDED | 1 | FORWARDED is used for flow events where the trace point has forwarded this packet or connection to the next processing entity. |
| DROPPED | 2 | DROPPED is used for flow events where the connection or packet has been dropped (e.g. due to a malformed packet, it being rejected by a network policy etc). The exact drop reason may be found in drop_reason_desc. |
| ERROR | 3 | ERROR is used for flow events where an error occurred during processing |
| AUDIT | 4 | AUDIT is used on policy verdict events in policy audit mode, to denominate flows that would have been dropped by policy if audit mode was turned off |
| REDIRECTED | 5 | REDIRECTED is used for flow events which have been redirected to the proxy |
| TRACED | 6 | TRACED is used for flow events which have been observed at a trace point, but no particular verdict has been reached yet |
| TRANSLATED | 7 | TRANSLATED is used for flow events where an address has been translated |


 

 

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

