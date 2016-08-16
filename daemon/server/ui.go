//
// Copyright 2016 Authors of Cilium
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
package server

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"

	"github.com/gorilla/websocket"
)

const (
	indexHTML = common.CiliumUIPath + "/index.html"

	writeWait = 10 * time.Second

	pongWait = 60 * time.Second

	pingPeriod = (pongWait * 9) / 10
)

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
)

func (router *Router) createUIHTMLIndex(w http.ResponseWriter, r *http.Request) {
	optsMap1 := types.OptionMap{}
	optsMap2 := types.OptionMap{}
	daemonConfig, err := router.daemon.Ping()
	if err == nil && daemonConfig.Opts != nil {
		var keys []string
		for k := range daemonConfig.Opts.Opts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i%2 == 0 {
				optsMap1[k] = daemonConfig.Opts.Opts[k]
			} else {
				optsMap2[k] = daemonConfig.Opts.Opts[k]
			}
		}
	}

	var ipStruct = struct {
		Opts1 types.OptionMap
		Opts2 types.OptionMap
	}{
		optsMap1,
		optsMap2,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	indexTempl, err := template.New("index.html").ParseFiles(indexHTML)
	if err != nil {
		processServerError(w, r, fmt.Errorf("Error parsing index.html file: %s", err))
		return
	}
	if err = indexTempl.Execute(w, &ipStruct); err != nil {
		processServerError(w, r, fmt.Errorf("Error processing UI template: %s", err))
	}
}

func writer(ws *websocket.Conn, uiMsgChan chan types.UIUpdateMsg) {
	pingTicker := time.NewTicker(pingPeriod)
	defer func() {
		pingTicker.Stop()
		ws.Close()
	}()
	for {
		select {
		case msg := <-uiMsgChan:
			ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := ws.WriteJSON(msg); err != nil {
				return
			}
		case <-pingTicker.C:
			ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := ws.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				return
			}
		}
	}
}

func reader(ws *websocket.Conn) {
	defer ws.Close()
	ws.SetReadLimit(512)
	ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error {
		ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (router *Router) webSocketUIStats(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		if _, ok := err.(websocket.HandshakeError); !ok {
			processServerError(w, r, fmt.Errorf("websocket error: %s", err))
		}
		return
	}

	uiChan, err := router.daemon.RegisterUIListener(ws)
	if err != nil {
		processServerError(w, r, fmt.Errorf("error from daemon while retrieving UI channel: %s", err))
		return
	}

	go writer(ws, uiChan)
	reader(ws)
}
