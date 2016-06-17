package server

import (
	"errors"
	"strings"
	"time"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	. "gopkg.in/check.v1"
)

var (
	lbls = types.Labels{
		"foo":    types.NewLabel("foo", "bar", common.CiliumLabelSource),
		"foo2":   types.NewLabel("foo2", "=bar2", common.CiliumLabelSource),
		"key":    types.NewLabel("key", "", common.CiliumLabelSource),
		"foo==":  types.NewLabel("foo==", "==", common.CiliumLabelSource),
		`foo\\=`: types.NewLabel(`foo\\=`, `\=`, common.CiliumLabelSource),
		`//=/`:   types.NewLabel(`//=/`, "", common.CiliumLabelSource),
		`%`:      types.NewLabel(`%`, `%ed`, common.CiliumLabelSource),
	}

	wantSecCtxLbls = types.SecCtxLabel{
		ID: 123,
		Containers: map[string]time.Time{
			"cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307": time.Now(),
		},
		Labels: lbls,
	}
)

func (s *DaemonSuite) TestGetLabelsIDOK(c *C) {
	s.d.OnPutLabels = func(lblsReceived types.Labels, contID string) (*types.SecCtxLabel, bool, error) {
		c.Assert(lblsReceived, DeepEquals, lbls)
		c.Assert(contID, Equals, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		return &wantSecCtxLbls, true, nil
	}

	secCtxLabl, _, err := s.c.PutLabels(lbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)
	c.Assert(*secCtxLabl, DeepEquals, wantSecCtxLbls)
}

func (s *DaemonSuite) TestGetLabelsIDFail(c *C) {
	s.d.OnPutLabels = func(lblsReceived types.Labels, contID string) (*types.SecCtxLabel, bool, error) {
		c.Assert(lblsReceived, DeepEquals, lbls)
		c.Assert(contID, Equals, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		return nil, false, errors.New("Reached maximum valid IDs")
	}

	_, _, err := s.c.PutLabels(lbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(strings.Contains(err.Error(), "Reached maximum valid IDs"), Equals, true)
}

func (s *DaemonSuite) TestGetLabelsOK(c *C) {
	s.d.OnGetLabels = func(id uint32) (*types.SecCtxLabel, error) {
		c.Assert(id, Equals, uint32(123))
		return &wantSecCtxLbls, nil
	}

	lblsReceived, err := s.c.GetLabels(123)
	c.Assert(err, Equals, nil)
	c.Assert(*lblsReceived, DeepEquals, wantSecCtxLbls)
}

func (s *DaemonSuite) TestGetLabelsFail(c *C) {
	s.d.OnGetLabels = func(id uint32) (*types.SecCtxLabel, error) {
		c.Assert(id, Equals, uint32(123))
		return nil, errors.New("Unable to contact consul")
	}

	_, err := s.c.GetLabels(123)
	c.Assert(strings.Contains(err.Error(), "Unable to contact consul"), Equals, true)
}

func (s *DaemonSuite) TestGetLabelsBySHA256OK(c *C) {
	s.d.OnGetLabelsBySHA256 = func(sha256sum string) (*types.SecCtxLabel, error) {
		c.Assert(sha256sum, Equals, "82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049")
		return &wantSecCtxLbls, nil
	}

	lblsReceived, err := s.c.GetLabelsBySHA256("82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049")
	c.Assert(err, Equals, nil)
	c.Assert(*lblsReceived, DeepEquals, wantSecCtxLbls)
}

func (s *DaemonSuite) TestGetLabelsBySHA256Fail(c *C) {
	s.d.OnGetLabelsBySHA256 = func(sha256sum string) (*types.SecCtxLabel, error) {
		c.Assert(sha256sum, Equals, "82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049")
		return nil, errors.New("Unable to contact consul")
	}

	_, err := s.c.GetLabelsBySHA256("82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049")
	c.Assert(strings.Contains(err.Error(), "Unable to contact consul"), Equals, true)
}

func (s *DaemonSuite) TestDeleteLabelsByUUIDOK(c *C) {
	s.d.OnDeleteLabelsByUUID = func(id uint32, contID string) error {
		c.Assert(id, Equals, uint32(123))
		c.Assert(contID, Equals, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		return nil
	}

	err := s.c.DeleteLabelsByUUID(123, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestDeleteLabelsByUUIDFail(c *C) {
	s.d.OnDeleteLabelsByUUID = func(id uint32, contID string) error {
		c.Assert(id, Equals, uint32(123))
		c.Assert(contID, Equals, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		return errors.New("Unable to contact consul")
	}

	err := s.c.DeleteLabelsByUUID(123, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(strings.Contains(err.Error(), "Unable to contact consul"), Equals, true)
}

func (s *DaemonSuite) TestDeleteLabelsBySHA256OK(c *C) {
	s.d.OnDeleteLabelsBySHA256 = func(sha256sum, contID string) error {
		c.Assert(sha256sum, Equals, "82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049")
		c.Assert(contID, Equals, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		return nil
	}

	err := s.c.DeleteLabelsBySHA256("82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049",
		"cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestDeleteLabelsBySHA256Fail(c *C) {
	s.d.OnDeleteLabelsBySHA256 = func(sha256sum, contID string) error {
		c.Assert(sha256sum, Equals, "82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049")
		c.Assert(contID, Equals, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		return errors.New("Unable to contact consul")
	}

	err := s.c.DeleteLabelsBySHA256("82078f981c61a5a71acbe92d38b2de3e3c5f7469450feab03d2739dfe6cbc049",
		"cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(strings.Contains(err.Error(), "Unable to contact consul"), Equals, true)
}

func (s *DaemonSuite) TestGetMaxOK(c *C) {
	s.d.OnGetMaxID = func() (uint32, error) {
		return 100, nil
	}

	maxID, err := s.c.GetMaxID()
	c.Assert(err, Equals, nil)
	c.Assert(maxID, Equals, uint32(100))
}

func (s *DaemonSuite) TestGetMaxIDFail(c *C) {
	s.d.OnGetMaxID = func() (uint32, error) {
		return 0, errors.New("Unable to contact consul")
	}

	_, err := s.c.GetMaxID()
	c.Assert(strings.Contains(err.Error(), "Unable to contact consul"), Equals, true, Commentf("error %s", err))
}
