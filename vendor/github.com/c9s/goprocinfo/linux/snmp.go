package linux

import (
	"io/ioutil"
	"reflect"
	"strconv"
	"strings"
)

type Snmp struct {
	// Ip
	IpForwarding      uint64 `json:"ip_forwarding"`
	IpDefaultTTL      uint64 `json:"ip_default_ttl"`
	IpInReceives      uint64 `json:"ip_in_receives"`
	IpInHdrErrors     uint64 `json:"ip_in_hdr_errors"`
	IpInAddrErrors    uint64 `json:"ip_in_addr_errors"`
	IpForwDatagrams   uint64 `json:"ip_forw_datagrams"`
	IpInUnknownProtos uint64 `json:"ip_in_unknown_protos"`
	IpInDiscards      uint64 `json:"ip_in_discards"`
	IpInDelivers      uint64 `json:"ip_in_delivers"`
	IpOutRequests     uint64 `json:"ip_out_requests"`
	IpOutDiscards     uint64 `json:"ip_out_discards"`
	IpOutNoRoutes     uint64 `json:"ip_out_no_routes"`
	IpReasmTimeout    uint64 `json:"ip_reasm_timeout"`
	IpReasmReqds      uint64 `json:"ip_reasm_reqds"`
	IpReasmOKs        uint64 `json:"ip_reasm_oks"`
	IpReasmFails      uint64 `json:"ip_reasm_fails"`
	IpFragOKs         uint64 `json:"ip_frag_oks"`
	IpFragFails       uint64 `json:"ip_frag_fails"`
	IpFragCreates     uint64 `json:"ip_frag_creates"`
	// Icmp
	IcmpInMsgs           uint64 `json:"icmp_in_msgs"`
	IcmpInErrors         uint64 `json:"icmp_in_errors"`
	IcmpInCsumErrors     uint64 `json:"icmp_in_csum_errors"`
	IcmpInDestUnreachs   uint64 `json:"icmp_in_dest_unreachs"`
	IcmpInTimeExcds      uint64 `json:"icmp_in_time_excds"`
	IcmpInParmProbs      uint64 `json:"icmp_in_parm_probs"`
	IcmpInSrcQuenchs     uint64 `json:"icmp_in_src_quenchs"`
	IcmpInRedirects      uint64 `json:"icmp_in_redirects"`
	IcmpInEchos          uint64 `json:"icmp_in_echos"`
	IcmpInEchoReps       uint64 `json:"icmp_in_echo_reps"`
	IcmpInTimestamps     uint64 `json:"icmp_in_timestamps"`
	IcmpInTimestampReps  uint64 `json:"icmp_in_timestamp_reps"`
	IcmpInAddrMasks      uint64 `json:"icmp_in_addr_masks"`
	IcmpInAddrMaskReps   uint64 `json:"icmp_in_addr_mask_reps"`
	IcmpOutMsgs          uint64 `json:"icmp_out_msgs"`
	IcmpOutErrors        uint64 `json:"icmp_out_errors"`
	IcmpOutDestUnreachs  uint64 `json:"icmp_out_dest_unreachs"`
	IcmpOutTimeExcds     uint64 `json:"icmp_out_time_excds"`
	IcmpOutParmProbs     uint64 `json:"icmp_out_parm_probs"`
	IcmpOutSrcQuenchs    uint64 `json:"icmp_out_src_quenchs"`
	IcmpOutRedirects     uint64 `json:"icmp_out_redirects"`
	IcmpOutEchos         uint64 `json:"icmp_out_echos"`
	IcmpOutEchoReps      uint64 `json:"icmp_out_echo_reps"`
	IcmpOutTimestamps    uint64 `json:"icmp_out_timestamps"`
	IcmpOutTimestampReps uint64 `json:"icmp_out_timestamp_reps"`
	IcmpOutAddrMasks     uint64 `json:"icmp_out_addr_masks"`
	IcmpOutAddrMaskReps  uint64 `json:"icmp_out_addr_mask_reps"`
	// IcmpMsg
	IcmpMsgInType0   uint64 `json:"icmpmsg_in_type0"`
	IcmpMsgInType3   uint64 `json:"icmpmsg_in_type3"`
	IcmpMsgInType5   uint64 `json:"icmpmsg_in_type5"`
	IcmpMsgInType8   uint64 `json:"icmpmsg_in_type8"`
	IcmpMsgInType11  uint64 `json:"icmpmsg_in_type11"`
	IcmpMsgInType13  uint64 `json:"icmpmsg_in_type13"`
	IcmpMsgOutType0  uint64 `json:"icmpmsg_out_type0"`
	IcmpMsgOutType3  uint64 `json:"icmpmsg_out_type3"`
	IcmpMsgOutType8  uint64 `json:"icmpmsg_out_type8"`
	IcmpMsgOutType14 uint64 `json:"icmpmsg_out_type14"`
	IcmpMsgOutType69 uint64 `json:"icmpmsg_out_type69"`
	// TCP
	TcpRtoAlgorithm uint64 `json:"tcp_rto_algorithm"`
	TcpRtoMin       uint64 `json:"tcp_rto_min"`
	TcpRtoMax       uint64 `json:"tcp_rto_max"`
	TcpMaxConn      uint64 `json:"tcp_max_conn"`
	TcpActiveOpens  uint64 `json:"tcp_active_opens"`
	TcpPassiveOpens uint64 `json:"tcp_passive_opens"`
	TcpAttemptFails uint64 `json:"tcp_attempt_fails"`
	TcpEstabResets  uint64 `json:"tcp_estab_resets"`
	TcpCurrEstab    uint64 `json:"tcp_curr_estab"`
	TcpInSegs       uint64 `json:"tcp_in_segs"`
	TcpOutSegs      uint64 `json:"tcp_out_segs"`
	TcpRetransSegs  uint64 `json:"tcp_retrans_segs"`
	TcpInErrs       uint64 `json:"tcp_in_errs"`
	TcpOutRsts      uint64 `json:"tcp_out_rsts"`
	TcpInCsumErrors uint64 `json:"tcp_in_csum_errors"`
	// UDP
	UdpInDatagrams  uint64 `json:"udp_in_datagrams"`
	UdpNoPorts      uint64 `json:"udp_no_ports"`
	UdpInErrors     uint64 `json:"udp_in_errors"`
	UdpOutDatagrams uint64 `json:"udp_out_datagrams"`
	UdpRcvbufErrors uint64 `json:"udp_rcvbuf_errors"`
	UdpSndbufErrors uint64 `json:"udp_sndbuf_errors"`
	UdpInCsumErrors uint64 `json:"udp_in_csum_errors"`
	// UDPLite
	UdpLiteInDatagrams  uint64 `json:"udp_lite_in_datagrams"`
	UdpLiteNoPorts      uint64 `json:"udp_lite_no_ports"`
	UdpLiteInErrors     uint64 `json:"udp_lite_in_errors"`
	UdpLiteOutDatagrams uint64 `json:"udp_lite_out_datagrams"`
	UdpLiteRcvbufErrors uint64 `json:"udp_lite_rcvbuf_errors"`
	UdpLiteSndbufErrors uint64 `json:"udp_lite_sndbuf_errors"`
	UdpLiteInCsumErrors uint64 `json:"udp_lite_in_csum_errors"`
}

func ReadSnmp(path string) (*Snmp, error) {
	data, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")

	// Maps an SNMP metric to its value (i.e. SyncookiesSent --> 0)
	statMap := make(map[string]string)

	// patterns
	// Ip: Forwarding DefaultTTL InReceives InHdrErrors... <-- header
	// Ip: 2 64 9305753793 0 0 0 0 0... <-- values

	for i := 1; i < len(lines); i = i + 2 {
		headers := strings.Fields(lines[i-1][strings.Index(lines[i-1], ":")+1:])
		values := strings.Fields(lines[i][strings.Index(lines[i], ":")+1:])
		protocol := strings.Replace(strings.Fields(lines[i-1])[0], ":", "", -1)

		for j, header := range headers {
			statMap[protocol+header] = values[j]
		}
	}

	var snmp Snmp = Snmp{}

	elem := reflect.ValueOf(&snmp).Elem()
	typeOfElem := elem.Type()

	for i := 0; i < elem.NumField(); i++ {
		if val, ok := statMap[typeOfElem.Field(i).Name]; ok {
			parsedVal, _ := strconv.ParseUint(val, 10, 64)
			elem.Field(i).SetUint(parsedVal)
		}
	}

	return &snmp, nil
}
