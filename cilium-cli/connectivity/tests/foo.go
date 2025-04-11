package tests

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
)

func Foo() check.Scenario {
	return &foobar{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type foobar struct {
	check.ScenarioBase
}

func (s *foobar) Filepath() string {
	return "howdy"
}
func (s *foobar) Name() string {
	return "foobar"
}

type slowWriter struct {
	c int
	b *bytes.Buffer
}

func (w *slowWriter) Write(p []byte) (n int, err error) {
	time.Sleep(15 * time.Second)
	return w.b.Write(p)
}

func (s *foobar) Run(ctx context.Context, t *check.Test) {
	for name, pod := range t.Context().CiliumPods() {
		fmt.Println("[tom-debug] starting tcpdump:", name)
		/*t.NewGenericAction(s, name).Run(func(_ *check.Action) {
			runHealthProbe(ctx, t, &pod)
		})*/
		//func (c *Client) ExecInPodWithWriters(connCtx, killCmdCtx context.Context, namespace, pod, container string, command []string, stdout, stderr io.Writer) error {
		sout := &slowWriter{b: &bytes.Buffer{}, c: 0}
		serr := &bytes.Buffer{}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
		defer cancel()
		err := pod.K8sClient.ExecInPodWithWriters(context.Background(), ctx,
			"kube-system", name, "cilium-agent",
			[]string{"tcpdump", "-i", "eth0", "--immediate-mode", "--print", "-w", "zzzap", "port 7777"},
			sout, serr)
		fmt.Println("Err:", err)
		fmt.Println("stdout:", sout.b.String())
		fmt.Println("stderr:", serr.String())
	}
}
