// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"fmt"
	"strings"

	. "github.com/cilium/checkmate"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/procfs"
)

type XFRMCollectorTest struct{}

var _ = Suite(&XFRMCollectorTest{})

var sampleStats = procfs.XfrmStat{
	XfrmInError:             1,
	XfrmInBufferError:       2,
	XfrmInHdrError:          3,
	XfrmInNoStates:          4,
	XfrmInStateProtoError:   5,
	XfrmInStateModeError:    6,
	XfrmInStateSeqError:     7,
	XfrmInStateExpired:      8,
	XfrmInStateMismatch:     9,
	XfrmInStateInvalid:      10,
	XfrmInTmplMismatch:      11,
	XfrmInNoPols:            12,
	XfrmInPolBlock:          13,
	XfrmInPolError:          14,
	XfrmOutError:            15,
	XfrmOutBundleGenError:   16,
	XfrmOutBundleCheckError: 17,
	XfrmOutNoStates:         18,
	XfrmOutStateProtoError:  19,
	XfrmOutStateModeError:   20,
	XfrmOutStateSeqError:    21,
	XfrmOutStateExpired:     22,
	XfrmOutPolBlock:         23,
	XfrmOutPolDead:          24,
	XfrmOutPolError:         25,
	XfrmFwdHdrError:         26,
	XfrmOutStateInvalid:     27,
	XfrmAcquireError:        28,
}

const (
	noErrorMetric = `
# HELP cilium_ipsec_xfrm_error Total number of xfrm errors
# TYPE cilium_ipsec_xfrm_error gauge
cilium_ipsec_xfrm_error{error="acquire",type="inbound"} 0
cilium_ipsec_xfrm_error{error="bundle_check",type="outbound"} 0
cilium_ipsec_xfrm_error{error="bundle_generation",type="outbound"} 0
cilium_ipsec_xfrm_error{error="forward_header",type="inbound"} 0
cilium_ipsec_xfrm_error{error="header",type="inbound"} 0
cilium_ipsec_xfrm_error{error="no_buffer",type="inbound"} 0
cilium_ipsec_xfrm_error{error="no_policy",type="inbound"} 0
cilium_ipsec_xfrm_error{error="no_state",type="inbound"} 0
cilium_ipsec_xfrm_error{error="no_state",type="outbound"} 0
cilium_ipsec_xfrm_error{error="other",type="inbound"} 0
cilium_ipsec_xfrm_error{error="other",type="outbound"} 0
cilium_ipsec_xfrm_error{error="policy",type="inbound"} 0
cilium_ipsec_xfrm_error{error="policy",type="outbound"} 0
cilium_ipsec_xfrm_error{error="policy_blocked",type="inbound"} 0
cilium_ipsec_xfrm_error{error="policy_blocked",type="outbound"} 0
cilium_ipsec_xfrm_error{error="policy_dead",type="outbound"} 0
cilium_ipsec_xfrm_error{error="state_expired",type="inbound"} 0
cilium_ipsec_xfrm_error{error="state_expired",type="outbound"} 0
cilium_ipsec_xfrm_error{error="state_invalid",type="inbound"} 0
cilium_ipsec_xfrm_error{error="state_invalid",type="outbound"} 0
cilium_ipsec_xfrm_error{error="state_mismatched",type="inbound"} 0
cilium_ipsec_xfrm_error{error="state_mode",type="inbound"} 0
cilium_ipsec_xfrm_error{error="state_mode",type="outbound"} 0
cilium_ipsec_xfrm_error{error="state_protocol",type="inbound"} 0
cilium_ipsec_xfrm_error{error="state_protocol",type="outbound"} 0
cilium_ipsec_xfrm_error{error="state_sequence",type="inbound"} 0
cilium_ipsec_xfrm_error{error="state_sequence",type="outbound"} 0
cilium_ipsec_xfrm_error{error="template_mismatched",type="inbound"} 0
`
	someErrorMetric = `
# HELP cilium_ipsec_xfrm_error Total number of xfrm errors
# TYPE cilium_ipsec_xfrm_error gauge
cilium_ipsec_xfrm_error{error="acquire",type="inbound"} 28
cilium_ipsec_xfrm_error{error="bundle_check",type="outbound"} 17
cilium_ipsec_xfrm_error{error="bundle_generation",type="outbound"} 16
cilium_ipsec_xfrm_error{error="forward_header",type="inbound"} 26
cilium_ipsec_xfrm_error{error="header",type="inbound"} 3
cilium_ipsec_xfrm_error{error="no_buffer",type="inbound"} 2
cilium_ipsec_xfrm_error{error="no_policy",type="inbound"} 12
cilium_ipsec_xfrm_error{error="no_state",type="inbound"} 4
cilium_ipsec_xfrm_error{error="no_state",type="outbound"} 18
cilium_ipsec_xfrm_error{error="other",type="inbound"} 1
cilium_ipsec_xfrm_error{error="other",type="outbound"} 15
cilium_ipsec_xfrm_error{error="policy",type="inbound"} 14
cilium_ipsec_xfrm_error{error="policy",type="outbound"} 25
cilium_ipsec_xfrm_error{error="policy_blocked",type="inbound"} 13
cilium_ipsec_xfrm_error{error="policy_blocked",type="outbound"} 23
cilium_ipsec_xfrm_error{error="policy_dead",type="outbound"} 24
cilium_ipsec_xfrm_error{error="state_expired",type="inbound"} 8
cilium_ipsec_xfrm_error{error="state_expired",type="outbound"} 22
cilium_ipsec_xfrm_error{error="state_invalid",type="inbound"} 10
cilium_ipsec_xfrm_error{error="state_invalid",type="outbound"} 27
cilium_ipsec_xfrm_error{error="state_mismatched",type="inbound"} 9
cilium_ipsec_xfrm_error{error="state_mode",type="inbound"} 6
cilium_ipsec_xfrm_error{error="state_mode",type="outbound"} 20
cilium_ipsec_xfrm_error{error="state_protocol",type="inbound"} 5
cilium_ipsec_xfrm_error{error="state_protocol",type="outbound"} 19
cilium_ipsec_xfrm_error{error="state_sequence",type="inbound"} 7
cilium_ipsec_xfrm_error{error="state_sequence",type="outbound"} 21
cilium_ipsec_xfrm_error{error="template_mismatched",type="inbound"} 11
`
)

func (x *XFRMCollectorTest) Test_xfrmCollector_Collect(c *C) {
	tests := []struct {
		name           string
		statsFn        func() (procfs.XfrmStat, error)
		expectedMetric string
		expectedCount  int
	}{
		{
			name: "error while getting stats",
			statsFn: func() (procfs.XfrmStat, error) {
				return procfs.XfrmStat{}, fmt.Errorf("error due to some reason")
			},
			expectedCount:  0,
			expectedMetric: "",
		},
		{
			name: "no data at all",
			statsFn: func() (procfs.XfrmStat, error) {
				return procfs.XfrmStat{}, nil
			},
			expectedCount:  28,
			expectedMetric: noErrorMetric,
		},
		{
			name: "some data",
			statsFn: func() (procfs.XfrmStat, error) {
				return sampleStats, nil
			},
			expectedCount:  28,
			expectedMetric: someErrorMetric,
		},
	}

	for _, tt := range tests {
		c.Log("Test : ", tt.name)
		collector := newXFRMCollector(tt.statsFn)

		// perform static checks such as prometheus naming convention, number of labels matching, etc
		lintProblems, err := testutil.CollectAndLint(collector)
		c.Assert(err, IsNil)
		c.Assert(lintProblems, HasLen, 0)

		// check the number of metrics
		count := testutil.CollectAndCount(collector)
		c.Assert(count, Equals, tt.expectedCount)

		// compare the metric output
		err = testutil.CollectAndCompare(collector, strings.NewReader(tt.expectedMetric))
		c.Assert(err, IsNil)
	}
}
