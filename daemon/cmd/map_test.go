// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/safeio"
)

type fakeMap struct {
	err error
}

func (m *fakeMap) DumpAndSubscribe(cb bpf.EventCallbackFunc, follow bool) (*bpf.Handle, error) {
	s, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
	if err != nil {
		panic(err)
	}
	cb(&bpf.Event{Timestamp: s})
	return nil, nil
}
func (m *fakeMap) IsEventsEnabled() bool { return true }

type fakeMapGetter struct {
	name string
	m    *fakeMap
}

func (g *fakeMapGetter) GetMap(name string) (eventsDumper, bool) {
	if name != g.name {
		return nil, false
	}
	return g.m, g.m != nil
}

type fakeProducer struct {
	data any
}

func (f *fakeProducer) Produce(w io.Writer, i any) error {
	f.data = i
	return nil
}

func Test_getMapNameEvents(t *testing.T) {
	assert := assert.New(t)
	eh := NewGetMapNameEventsHandler(&Daemon{}, &fakeMapGetter{
		name: "test_map_name",
		m:    &fakeMap{},
	})
	req, err := http.NewRequest(http.MethodGet, "https://localhost/v1/map/test_map_name/events", nil)
	assert.NoError(err)
	restreq := restapi.GetMapNameEventsParams{
		HTTPRequest: req,
		Name:        "test_map_name",
	}
	resp := eh.Handle(restreq)
	w := httptest.NewRecorder()
	mw := &metrics.ResponderWrapper{
		ResponseWriter: w,
	}
	fp := &fakeProducer{}
	resp.WriteResponse(mw, fp)
	d, err := safeio.ReadAllLimit(w.Body, safeio.MB)
	assert.NoError(err)
	assert.Equal(`{"action":"update","desired-action":"sync","key":"\u003cnil\u003e","last-error":"\u003cnil\u003e","timestamp":"2006-01-02T15:04:05.000Z","value":"\u003cnil\u003e"}`+"\n", string(d))
}

func Test_getMapNameEventsMapErrors(t *testing.T) {
	assert := assert.New(t)
	m := &fakeMap{err: fmt.Errorf("test0")}
	eh := NewGetMapNameEventsHandler(&Daemon{}, &fakeMapGetter{
		m: m,
	})
	req, err := http.NewRequest(http.MethodGet, "https://localhost/v1/map/test_map_name_fake/events", nil)
	assert.NoError(err)
	restreq := restapi.GetMapNameEventsParams{
		HTTPRequest: req,
		Name:        "test_map_name_fake",
	}
	resp := eh.Handle(restreq)
	w := httptest.NewRecorder()
	fp := &fakeProducer{}
	resp.WriteResponse(w, fp)
	assert.Equal(http.StatusNotFound, w.Code)
}
