// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// +build privileged_tests

package api

import (
	"io/ioutil"
	"os"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type ProbesAPITestSuite struct{}

var _ = Suite(&ProbesAPITestSuite{})

func (b *ProbesAPITestSuite) TestKprobe(c *C) {
	sourceFile, err := ioutil.TempFile("/tmp", "cilium_kprobe_test_")
	c.Assert(err, IsNil)
	defer os.Remove(sourceFile.Name())

	const source string = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>

BPF_HASH(currsock, u32, struct sock *);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();

	currsock.update(&pid, &sk);

	return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;

	skpp = currsock.lookup(&pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		currsock.delete(&pid);
		return 0;
	}

	// pull in details
	struct sock *skp = *skpp;
	u32 saddr = skp->__sk_common.skc_rcv_saddr;
	u32 daddr = skp->__sk_common.skc_daddr;
	u16 dport = skp->__sk_common.skc_dport;

	// output
	bpf_trace_printk("trace_tcp4connect %x %x %d\\n", saddr, daddr, ntohs(dport));

	currsock.delete(&pid);

	return 0;
};
`
	_, err = sourceFile.Write([]byte(source))
	c.Assert(err, IsNil)

	probeProg := ProbeProg{
		SourceFilename: sourceFile.Name(),
		Probes: []ProbeAttachment{
			{
				Typ:       KProbeType,
				FuncName:  "kprobe__tcp_v4_connect",
				ProbeName: "tcp_v4_connect",
			},
			{
				Typ:       KRetProbeType,
				FuncName:  "kretprobe__tcp_v4_connect",
				ProbeName: "tcp_v4_connect",
			},
		},
	}

	err = probeProg.LoadAndAttach()
	c.Assert(err, IsNil)

	probeProg.Close()
}
