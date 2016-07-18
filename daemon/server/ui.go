package server

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	"github.com/gorilla/websocket"
)

const (
	// FIXME fix [{{.IP}}] that we should derive it from server IP received packet
	indexHTML = common.CiliumUIPath + "index.html"

	writeWait = 10 * time.Second

	pongWait = 60 * time.Second

	pingPeriod = (pongWait * 9) / 10
)

var (
	indexTempl *template.Template
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
)

func init() {
	var err error
	indexTempl, err = template.New("index.html").ParseFiles(indexHTML)
	if err != nil {
		log.Errorf("Error parsing index.html file: %s", err)
	}
}

func (router *Router) createUIHTMLIndex(w http.ResponseWriter, r *http.Request) {
	tcpAddr, err := router.daemon.GetUIIP()
	if err != nil {
		processServerError(w, r, err)
	}
	var addr string
	if tcpAddr.IP.To4() != nil {
		addr = tcpAddr.IP.String() + ":" + strconv.Itoa(tcpAddr.Port)
	} else {
		addr = "[" + tcpAddr.IP.String() + "]:" + strconv.Itoa(tcpAddr.Port)
	}

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
			if i % 2 == 0 {
				optsMap1[k] = daemonConfig.Opts.Opts[k]
			} else {
				optsMap2[k] = daemonConfig.Opts.Opts[k]
			}
		}
	}

	var ipStruct = struct {
		TCPAddr string
		Opts1   types.OptionMap
		Opts2   types.OptionMap
	}{
		addr,
		optsMap1,
		optsMap2,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if indexTempl == nil {
		log.Error("Unable read index.html template due to former error")
	} else {
		if err = indexTempl.Execute(w, &ipStruct); err != nil {
			log.Errorf("Error processing UI template: %s", err)
		}
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
	}

	go writer(ws, uiChan)
	reader(ws)
}
