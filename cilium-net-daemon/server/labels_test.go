package server

import (
	"errors"
	"reflect"
	"strings"

	"github.com/noironetworks/cilium-net/common/types"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

var (
	lbls = types.Labels{
		"foo":    "bar",
		"foo2":   "=bar2",
		"key":    "",
		"foo==":  "==",
		`foo\\=`: `\=`,
		`//=/`:   "",
		`%`:      `%ed`,
	}
)

func (s *DaemonSuite) TestGetLabelsIDOK(c *C) {
	s.d.OnGetLabelsID = func(lblsReceived types.Labels) (int, error) {
		c.Assert(reflect.DeepEqual(lblsReceived, lbls), Equals, true)
		return 123, nil
	}

	id, err := s.c.GetLabelsID(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, 123)
}

func (s *DaemonSuite) TestGetLabelsIDFail(c *C) {
	s.d.OnGetLabelsID = func(lblsReceived types.Labels) (int, error) {
		c.Assert(reflect.DeepEqual(lblsReceived, lbls), Equals, true)
		return -1, errors.New("Reached maximum valid IDs")
	}

	_, err := s.c.GetLabelsID(lbls)
	c.Assert(strings.Contains(err.Error(), "Reached maximum valid IDs"), Equals, true)
}

func (s *DaemonSuite) TestGetLabelsOK(c *C) {
	s.d.OnGetLabels = func(id int) (*types.Labels, error) {
		c.Assert(id, Equals, 123)
		return &lbls, nil
	}

	lblsReceived, err := s.c.GetLabels(123)
	c.Assert(err, Equals, nil)
	c.Assert(reflect.DeepEqual(*lblsReceived, lbls), Equals, true)
}

func (s *DaemonSuite) TestGetLabelsFail(c *C) {
	s.d.OnGetLabels = func(id int) (*types.Labels, error) {
		c.Assert(id, Equals, 123)
		return nil, errors.New("Unable to contact consul")
	}

	_, err := s.c.GetLabels(123)
	c.Assert(strings.Contains(err.Error(), "Unable to contact consul"), Equals, true)
}
