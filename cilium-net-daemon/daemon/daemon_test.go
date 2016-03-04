package daemon

import (
	"testing"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type DaemonSuite struct {
	d *Daemon
}

var _ = Suite(&DaemonSuite{})

func (s *DaemonSuite) TestGetValidPrefixes(c *C) {
	d := Daemon{validLabelPrefixes: []string{"io.cilium"}}
	allLabels := map[string]string{
		"io.kubernetes.container.hash":                   "cf58006d",
		"io.kubernetes.container.name":                   "POD",
		"io.kubernetes.container.restartCount":           "0",
		"io.kubernetes.container.terminationMessagePath": "",
		"io.kubernetes.pod.name":                         "my-nginx-3800858182-07i3n",
		"io.kubernetes.pod.namespace":                    "default",
		"io.kubernetes.pod.terminationGracePeriod":       "30",
		"io.kubernetes.pod.uid":                          "c2e22414-dfc3-11e5-9792-080027755f5a",
	}
	filtered := d.filterValidLabels(allLabels)
	c.Assert(len(filtered), Equals, 0)
	allLabels["io.cilium.lizards"] = "web"
	filtered = d.filterValidLabels(allLabels)
	c.Assert(len(filtered), Equals, 1)
	c.Assert(filtered, DeepEquals, map[string]string{"io.cilium.lizards": "web"})
}
