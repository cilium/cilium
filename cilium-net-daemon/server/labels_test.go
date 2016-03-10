package server

import (
	"errors"
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
	s.d.OnGetLabelsID = func(lblsReceived types.Labels) (int, bool, error) {
		c.Assert(lblsReceived, DeepEquals, lbls)
		return 123, true, nil
	}

	id, _, err := s.c.GetLabelsID(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, 123)
}

func (s *DaemonSuite) TestGetLabelsIDFail(c *C) {
	s.d.OnGetLabelsID = func(lblsReceived types.Labels) (int, bool, error) {
		c.Assert(lblsReceived, DeepEquals, lbls)
		return -1, false, errors.New("Reached maximum valid IDs")
	}

	_, _, err := s.c.GetLabelsID(lbls)
	c.Assert(strings.Contains(err.Error(), "Reached maximum valid IDs"), Equals, true)
}

func (s *DaemonSuite) TestGetLabelsOK(c *C) {
	s.d.OnGetLabels = func(id int) (*types.Labels, error) {
		c.Assert(id, Equals, 123)
		return &lbls, nil
	}

	lblsReceived, err := s.c.GetLabels(123)
	c.Assert(err, Equals, nil)
	c.Assert(*lblsReceived, DeepEquals, lbls)
}

func (s *DaemonSuite) TestGetLabelsFail(c *C) {
	s.d.OnGetLabels = func(id int) (*types.Labels, error) {
		c.Assert(id, Equals, 123)
		return nil, errors.New("Unable to contact consul")
	}

	_, err := s.c.GetLabels(123)
	c.Assert(strings.Contains(err.Error(), "Unable to contact consul"), Equals, true)
}

func (s *DaemonSuite) TestGetMaxOK(c *C) {
	s.d.OnGetMaxID = func() (int, error) {
		return 100, nil
	}

	maxID, err := s.c.GetMaxID()
	c.Assert(err, Equals, nil)
	c.Assert(maxID, Equals, 100)
}

func (s *DaemonSuite) TestGetMaxIDFail(c *C) {
	s.d.OnGetMaxID = func() (int, error) {
		return -1, errors.New("Unable to contact consul")
	}

	_, err := s.c.GetMaxID()
	c.Assert(strings.Contains(err.Error(), "Unable to contact consul"), Equals, true, Commentf("error %s", err))
}
