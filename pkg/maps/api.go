// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/metrics"
)

type eventsDumper interface {
	DumpAndSubscribe(cb bpf.EventCallbackFunc, follow bool) (*bpf.Handle, error)
	IsEventsEnabled() bool
}

type mapRefGetter interface {
	GetMap(name string) (eventsDumper, bool)
}

type mapGetterImpl struct{}

func (mg mapGetterImpl) GetMap(name string) (eventsDumper, bool) {
	m := bpf.GetMap(name)
	return m, m != nil
}

// TODO: This will be easy to break, is there a way we can refactor to make changes to metrics.ResponderWrapper fail
// fail at compile time?
func getFlusher(w http.ResponseWriter) (http.Flusher, error) {
	wrapper, ok := w.(*metrics.ResponderWrapper)
	if !ok {
		return nil, fmt.Errorf("expected ResponseWriter to be of type *metrics.ResponseWrapper: %T", w)
	}

	f, ok := wrapper.ResponseWriter.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("failed to get http.Flusher from ResponseWriter: %T", w)
	}
	return f, nil
}

type flushWriter struct {
	f http.Flusher
	w io.Writer
}

func (fw *flushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if fw.f != nil {
		fw.f.Flush()
	}
	return
}

type getMapNameEventsHandler struct {
	logger    logrus.FieldLogger
	mapGetter mapRefGetter
}

func (h *getMapNameEventsHandler) Handle(params restapi.GetMapNameEventsParams) middleware.Responder {
	follow := false
	if params.Follow != nil {
		follow = *params.Follow
	}
	m, exists := h.mapGetter.GetMap(params.Name)
	if !exists || !m.IsEventsEnabled() {
		return restapi.NewGetMapNameNotFound()
	}

	return middleware.ResponderFunc(func(w http.ResponseWriter, _ runtime.Producer) {
		flusher, err := getFlusher(w)
		if err != nil {
			h.logger.WithError(err).Error("BUG: could not get flushed from ResponseWriter")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		enc := json.NewEncoder(&flushWriter{f: flusher, w: w})

		writeEventFn := func(e *bpf.Event) {
			errStr := "<nil>"
			if e.GetLastError() != nil {
				errStr = e.GetLastError().Error()
			}
			err := enc.Encode(&models.MapEvent{
				Key:           e.GetKey(),
				Action:        e.GetAction(),
				Value:         e.GetValue(),
				LastError:     errStr,
				Timestamp:     strfmt.DateTime(e.Timestamp),
				DesiredAction: e.GetDesiredAction().String(),
			})
			if err != nil {
				panic(err)
			}
			flusher.Flush()
		}

		handle, err := m.DumpAndSubscribe(writeEventFn, follow)
		if err != nil {
			h.logger.WithError(err).Error("api handler failed to subscribe to map events")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if follow && h != nil {
			go func() {
				<-params.HTTPRequest.Context().Done()
				handle.Close()
			}()
			for e := range handle.C() {
				writeEventFn(e)
			}
		}
	})
}

type getMapNameHandler struct{}

func (h *getMapNameHandler) Handle(params restapi.GetMapNameParams) middleware.Responder {
	m := bpf.GetMap(params.Name)
	if m == nil {
		return restapi.NewGetMapNameNotFound()
	}

	return restapi.NewGetMapNameOK().WithPayload(m.GetModel())
}

type getMapHandler struct{}

func (h *getMapHandler) Handle(params restapi.GetMapParams) middleware.Responder {
	mapList := &models.BPFMapList{
		Maps: append(bpf.GetOpenMaps(), ebpf.GetOpenMaps()...),
	}

	return restapi.NewGetMapOK().WithPayload(mapList)
}
