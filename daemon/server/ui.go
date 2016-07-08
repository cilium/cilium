package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/noironetworks/cilium-net/common/types"

	"github.com/gorilla/websocket"
)

const (
	// FIXME fix [{{.IP}}] that we should derive it from server IP received packet
	indexHTML = `<!DOCTYPE html>
<html>
	<head>
		<script type="text/javascript" src="./static/vis.min.js"></script>
		<script type="text/javascript" src="./static/vis.animatetraffic.js"></script>
		<link href="./static/vis.min.css" rel="stylesheet" type="text/css" />

		<style type="text/css">
			#cilium-topology {
				border: 1px solid lightgray;
			        padding: 0px; margin: 0px; height: 100%; text-align: center;
			}
			html, body { padding: 0px; margin: 0px; height: 100%; text-align: center; }
		</style>
	</head>
	<body>
		<div id="cilium-topology"></div>

		<script type="text/javascript">
			var network;

			nodesArray = [];
			edgesArray = [];

			nodes = new vis.DataSet(nodesArray);
			edges = new vis.DataSet(edgesArray);

			var container = document.getElementById('cilium-topology');

			var data = {
				nodes : nodes,
				edges : edges
			};

			var options = {
				//"configure": {},
				"nodes" : {
					"font" : {
						"size" : 12,
						"strokeWidth" : 2,
						"strokeColor" : "rgba(255,255,255,1)"
					},
					"shape" : "dot"
				},
				"edges" : {
					"color" : {
						"highlight" : "rgba(117,196,255,1)",
						"inherit" : false,
						"opacity" : 0.65
					},
					"arrows" : {
						"to" : {
							"enabled" : true
						}
					},
					"shadow" : {
						"enabled" : true
					},
					"arrowStrikethrough" : false,
					"smooth" : {
						"forceDirection" : "none"
					},
					"scaling": {
						"min": 1,
    					}
				},
				"physics" : {
					"minVelocity" : 0.75,
					"stabilization" : {
						"enabled" : true,
						"iterations" : 10
					}
				}
			};
			function startNetwork() {
				network = new vis.Network(container, data, options);
			}

			startNetwork();

			network.on("afterDrawing", function (ctx) {
				var ids = nodes.getIds();
				for (i = 0; i < ids.length; i++) {
					nodeId = ids[i];
					var nodePosition = network.getPositions([nodeId]);
					ctx.fillStyle = "black";
					ctx.textAlign = "center";
					ctx.textBaseline = "middle";
					ctx.fillText(nodes.get(nodeId).image, nodePosition[nodeId].x, nodePosition[nodeId].y);
				}
			});

			(function() {
				var networkDiv = document.getElementById("cilium-topology");
				var conn = new WebSocket("ws://{{.TCPAddr}}/ws");
				conn.onclose = function(evt) {
					networkDiv.textContent = 'Connection closed';
				};
				conn.onmessage = function(evt) {
					var msg = JSON.parse(evt.data);
					console.log('msg', msg);
					console.log('node', msg.node);
					switch(msg.type) {
					case "add-node":
						nodes.add(msg.node);
						break;
					case "mod-node":
						nodes.update(msg.node);
						break;
					case "del-node":
						nodes.remove({
							id : msg.id
						});
						break;
					case "add-edge":
						edges.add(msg.edge);
						break;
					case "mod-edge":
						edges.update(msg.edge);
						break;
					case "animate-edge":
						network.animateTraffic(msg.edges);
					case "del-edge":
						edges.remove({
							id : msg.id
						});
						break;
					}
				};
			})();
		</script>
	</body>
</html>
`
	writeWait = 10 * time.Second

	pongWait = 60 * time.Second

	pingPeriod = (pongWait * 9) / 10
)

var (
	indexTempl = template.Must(template.New("").Parse(indexHTML))
	upgrader   = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
)

func (router *RouterUI) createUIHTMLIndex(w http.ResponseWriter, r *http.Request) {
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

	var ipStruct = struct {
		TCPAddr string
	}{
		addr,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	indexTempl.Execute(w, &ipStruct)
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
	ws.SetPongHandler(func(string) error { ws.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (router *RouterUI) webSocketUIStats(w http.ResponseWriter, r *http.Request) {
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
