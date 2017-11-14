package linux

import (
	"io/ioutil"
	"reflect"
	"strconv"
	"strings"
)

type NetStat struct {
	// TcpExt
	SyncookiesSent            uint64 `json:"syncookie_sent"`
	SyncookiesRecv            uint64 `json:"syncookies_recv"`
	SyncookiesFailed          uint64 `json:"syncookies_failed"`
	EmbryonicRsts             uint64 `json:"embryonic_rsts"`
	PruneCalled               uint64 `json:"prune_called"`
	RcvPruned                 uint64 `json:"rcv_pruned"`
	OfoPruned                 uint64 `json:"ofo_pruned"`
	OutOfWindowIcmps          uint64 `json:"out_of_window_icmps"`
	LockDroppedIcmps          uint64 `json:"lock_dropped_icmps"`
	ArpFilter                 uint64 `json:"arp_filter"`
	TW                        uint64 `json:"tw"`
	TWRecycled                uint64 `json:"tw_recycled"`
	TWKilled                  uint64 `json:"tw_killed"`
	PAWSPassive               uint64 `json:"paws_passive"`
	PAWSActive                uint64 `json:"paws_active"`
	PAWSEstab                 uint64 `json:"paws_estab"`
	DelayedACKs               uint64 `json:"delayed_acks"`
	DelayedACKLocked          uint64 `json:"delayed_ack_locked"`
	DelayedACKLost            uint64 `json:"delayed_ack_lost"`
	ListenOverflows           uint64 `json:"listen_overflows"`
	ListenDrops               uint64 `json:"listen_drops"`
	TCPPrequeued              uint64 `json:"tcp_prequeued"`
	TCPDirectCopyFromBacklog  uint64 `json:"tcp_direct_copy_from_backlog"`
	TCPDirectCopyFromPrequeue uint64 `json:"tcp_direct_copy_from_prequeue"`
	TCPPrequeueDropped        uint64 `json:"tcp_prequeue_dropped"`
	TCPHPHits                 uint64 `json:"tcp_hp_hits"`
	TCPHPHitsToUser           uint64 `json:"tcp_hp_hits_to_user"`
	TCPPureAcks               uint64 `json:"tcp_pure_acks"`
	TCPHPAcks                 uint64 `json:"tcp_hp_acks"`
	TCPRenoRecovery           uint64 `json:"tcp_reno_recovery"`
	TCPSackRecovery           uint64 `json:"tcp_sack_recovery"`
	TCPSACKReneging           uint64 `json:"tcp_sack_reneging"`
	TCPFACKReorder            uint64 `json:"tcp_fack_reorder"`
	TCPSACKReorder            uint64 `json:"tcp_sack_reorder"`
	TCPRenoReorder            uint64 `json:"tcp_reno_reorder"`
	TCPTSReorder              uint64 `json:"tcp_ts_reorder"`
	TCPFullUndo               uint64 `json:"tcp_full_undo"`
	TCPPartialUndo            uint64 `json:"tcp_partial_undo"`
	TCPDSACKUndo              uint64 `json:"tcp_dsack_undo"`
	TCPLossUndo               uint64 `json:"tcp_loss_undo"`
	TCPLoss                   uint64 `json:"tcp_loss"`
	TCPLostRetransmit         uint64 `json:"tcp_lost_retransmit"`
	TCPRenoFailures           uint64 `json:"tcp_reno_failures"`
	TCPSackFailures           uint64 `json:"tcp_sack_failures"`
	TCPLossFailures           uint64 `json:"tcp_loss_failures"`
	TCPFastRetrans            uint64 `json:"tcp_fast_retrans"`
	TCPForwardRetrans         uint64 `json:"tcp_forward_retrans"`
	TCPSlowStartRetrans       uint64 `json:"tcp_slow_start_retrans"`
	TCPTimeouts               uint64 `json:"tcp_timeouts"`
	TCPLossProbes             uint64 `json:"tcp_loss_probes"`
	TCPLossProbeRecovery      uint64 `json:"tcp_loss_probe_recovery"`
	TCPRenoRecoveryFail       uint64 `json:"tcp_reno_recovery_fail"`
	TCPSackRecoveryFail       uint64 `json:"tcp_sack_recovery_fail"`
	TCPSchedulerFailed        uint64 `json:"tcp_scheduler_failed"`
	TCPRcvCollapsed           uint64 `json:"tcp_rcv_collapsed"`
	TCPDSACKOldSent           uint64 `json:"tcp_dsack_old_sent"`
	TCPDSACKOfoSent           uint64 `json:"tcp_dsack_ofo_sent"`
	TCPDSACKRecv              uint64 `json:"tcp_dsack_recv"`
	TCPDSACKOfoRecv           uint64 `json:"tcp_dsack_ofo_recv"`
	TCPAbortOnSyn             uint64 `json:"tcp_abort_on_syn"`
	TCPAbortOnData            uint64 `json:"tcp_abort_on_data"`
	TCPAbortOnClose           uint64 `json:"tcp_abort_on_close"`
	TCPAbortOnMemory          uint64 `json:"tcp_abort_on_memory"`
	TCPAbortOnTimeout         uint64 `json:"tcp_abort_on_timeout"`
	TCPAbortOnLinger          uint64 `json:"tcp_abort_on_linger"`
	TCPAbortFailed            uint64 `json:"tcp_abort_failed"`
	TCPMemoryPressures        uint64 `json:"tcp_memory_pressures"`
	TCPSACKDiscard            uint64 `json:"tcp_sack_discard"`
	TCPDSACKIgnoredOld        uint64 `json:"tcp_dsack_ignored_old"`
	TCPDSACKIgnoredNoUndo     uint64 `json:"tcp_dsack_ignored_no_undo"`
	TCPSpuriousRTOs           uint64 `json:"tcp_spurious_rtos"`
	TCPMD5NotFound            uint64 `json:"tcp_md5_not_found"`
	TCPMD5Unexpected          uint64 `json:"tcp_md5_unexpected"`
	TCPSackShifted            uint64 `json:"tcp_sack_shifted"`
	TCPSackMerged             uint64 `json:"tcp_sack_merged"`
	TCPSackShiftFallback      uint64 `json:"tcp_sack_shift_fallback"`
	TCPBacklogDrop            uint64 `json:"tcp_backlog_drop"`
	TCPMinTTLDrop             uint64 `json:"tcp_min_ttl_drop"`
	TCPDeferAcceptDrop        uint64 `json:"tcp_defer_accept_drop"`
	IPReversePathFilter       uint64 `json:"ip_reverse_path_filter"`
	TCPTimeWaitOverflow       uint64 `json:"tcp_time_wait_overflow"`
	TCPReqQFullDoCookies      uint64 `json:"tcp_req_q_full_do_cookies"`
	TCPReqQFullDrop           uint64 `json:"tcp_req_q_full_drop"`
	TCPRetransFail            uint64 `json:"tcp_retrans_fail"`
	TCPRcvCoalesce            uint64 `json:"tcp_rcv_coalesce"`
	TCPOFOQueue               uint64 `json:"tcp_ofo_drop"`
	TCPOFODrop                uint64 `json:"tcp_ofo_drop"`
	TCPOFOMerge               uint64 `json:"tcp_ofo_merge"`
	TCPChallengeACK           uint64 `json:"tcp_challenge_ack"`
	TCPSYNChallenge           uint64 `json:"tcp_syn_challenge"`
	TCPFastOpenActive         uint64 `json:"tcp_fast_open_active"`
	TCPFastOpenActiveFail     uint64 `json:"tcp_fast_open_active_fail"`
	TCPFastOpenPassive        uint64 `json:"tcp_fast_open_passive"`
	TCPFastOpenPassiveFail    uint64 `json:"tcp_fast_open_passive_fail"`
	TCPFastOpenListenOverflow uint64 `json:"tcp_fast_open_listen_overflow"`
	TCPFastOpenCookieReqd     uint64 `json:"tcp_fast_open_cookie_reqd"`
	TCPSpuriousRtxHostQueues  uint64 `json:"tcp_spurious_rtx_host_queues"`
	BusyPollRxPackets         uint64 `json:"busy_poll_rx_packets"`
	TCPAutoCorking            uint64 `json:"tcp_auto_corking"`
	TCPFromZeroWindowAdv      uint64 `json:"tcp_from_zero_window_adv"`
	TCPToZeroWindowAdv        uint64 `json:"tcp_to_zero_window_adv"`
	TCPWantZeroWindowAdv      uint64 `json:"tcp_want_zero_window_adv"`
	TCPSynRetrans             uint64 `json:"tcp_syn_retrans"`
	TCPOrigDataSent           uint64 `json:"tcp_orig_data_sent"`
	// IpExt
	InNoRoutes      uint64 `json:"in_no_routes"`
	InTruncatedPkts uint64 `json:"in_truncated_pkts"`
	InMcastPkts     uint64 `json:"in_mcast_pkts"`
	OutMcastPkts    uint64 `json:"out_mcast_pkts"`
	InBcastPkts     uint64 `json:"in_bcast_pkts"`
	OutBcastPkts    uint64 `json:"out_bcast_pkts"`
	InOctets        uint64 `json:"in_octets"`
	OutOctets       uint64 `json:"out_octets"`
	InMcastOctets   uint64 `json:"in_mcast_octets"`
	OutMcastOctets  uint64 `json:"out_mcast_octets"`
	InBcastOctets   uint64 `json:"in_bcast_octets"`
	OutBcastOctets  uint64 `json:"out_bcast_octets"`
	InCsumErrors    uint64 `json:"in_csum_errors"`
	InNoECTPkts     uint64 `json:"in_no_ect_pkts"`
	InECT1Pkts      uint64 `json:"in_ect1_pkts"`
	InECT0Pkts      uint64 `json:"in_ect0_pkts"`
	InCEPkts        uint64 `json:"in_ce_pkts"`
}

func ReadNetStat(path string) (*NetStat, error) {
	data, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")

	// Maps a netstat metric to its value (i.e. SyncookiesSent --> 0)
	statMap := make(map[string]string)

	// patterns
	// TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed... <-- header
	// TcpExt: 0 0 1764... <-- values

	for i := 1; i < len(lines); i = i + 2 {
		headers := strings.Fields(lines[i-1][strings.Index(lines[i-1], ":")+1:])
		values := strings.Fields(lines[i][strings.Index(lines[i], ":")+1:])

		for j, header := range headers {
			statMap[header] = values[j]
		}
	}

	var netstat NetStat = NetStat{}

	elem := reflect.ValueOf(&netstat).Elem()
	typeOfElem := elem.Type()

	for i := 0; i < elem.NumField(); i++ {
		if val, ok := statMap[typeOfElem.Field(i).Name]; ok {
			parsedVal, _ := strconv.ParseUint(val, 10, 64)
			elem.Field(i).SetUint(parsedVal)
		}
	}

	return &netstat, nil
}
