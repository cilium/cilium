package xfer

import (
	"io"
	"net/http"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/websocket"
	"github.com/ugorji/go/codec"

	"github.com/weaveworks/scope/common/mtime"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer. Needs to be less
	// than the idle timeout on whatever frontend server is proxying the
	// websocket connections (e.g. nginx).
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait. The peer
	// must respond with a pong in < pongWait. But it may take writeWait for the
	// pong to be sent. Therefore we want to allow time for that, and a bit of
	// delay/round-trip in case the peer is busy. 1/3 of pongWait seems like a
	// reasonable amount of time to respond to a ping.
	pingPeriod = ((pongWait - writeWait) * 2 / 3)
)

// Websocket exposes the bits of *websocket.Conn we actually use.
type Websocket interface {
	ReadMessage() (messageType int, p []byte, err error)
	WriteMessage(messageType int, data []byte) error
	ReadJSON(v interface{}) error
	WriteJSON(v interface{}) error
	Close() error
}

type pingingWebsocket struct {
	pinger    *time.Timer
	readLock  sync.Mutex
	writeLock sync.Mutex
	conn      *websocket.Conn
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Upgrade upgrades the HTTP server connection to the WebSocket protocol.
func Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (Websocket, error) {
	wsConn, err := upgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		return nil, err
	}
	return Ping(wsConn), nil
}

// WSDialer can dial a new websocket
type WSDialer interface {
	Dial(urlStr string, requestHeader http.Header) (*websocket.Conn, *http.Response, error)
}

// DialWS creates a new client connection. Use requestHeader to specify the
// origin (Origin), subprotocols (Sec-WebSocket-Protocol) and cookies (Cookie).
// Use the response.Header to get the selected subprotocol
// (Sec-WebSocket-Protocol) and cookies (Set-Cookie).
func DialWS(d WSDialer, urlStr string, requestHeader http.Header) (Websocket, *http.Response, error) {
	wsConn, resp, err := d.Dial(urlStr, requestHeader)
	if err != nil {
		return nil, resp, err
	}
	return Ping(wsConn), resp, nil
}

// Ping adds a periodic ping to a websocket connection.
func Ping(c *websocket.Conn) Websocket {
	p := &pingingWebsocket{conn: c}
	p.conn.SetPongHandler(p.pong)
	p.conn.SetReadDeadline(mtime.Now().Add(pongWait))
	p.pinger = time.AfterFunc(pingPeriod, p.ping)
	return p
}

func (p *pingingWebsocket) ping() {
	p.writeLock.Lock()
	defer p.writeLock.Unlock()
	if err := p.conn.WriteControl(websocket.PingMessage, nil, mtime.Now().Add(writeWait)); err != nil {
		log.Errorf("websocket ping error: %v", err)
		p.conn.Close()
		return
	}
	p.pinger.Reset(pingPeriod)
}

func (p *pingingWebsocket) pong(string) error {
	p.conn.SetReadDeadline(mtime.Now().Add(pongWait))
	return nil
}

// ReadMessage is a helper method for getting a reader using NextReader and
// reading from that reader to a buffer.
func (p *pingingWebsocket) ReadMessage() (int, []byte, error) {
	p.readLock.Lock()
	defer p.readLock.Unlock()
	return p.conn.ReadMessage()
}

// WriteMessage is a helper method for getting a writer using NextWriter,
// writing the message and closing the writer.
func (p *pingingWebsocket) WriteMessage(messageType int, data []byte) error {
	p.writeLock.Lock()
	defer p.writeLock.Unlock()
	if err := p.conn.SetWriteDeadline(mtime.Now().Add(writeWait)); err != nil {
		return err
	}
	return p.conn.WriteMessage(messageType, data)
}

// WriteJSON writes the JSON encoding of v to the connection.
func (p *pingingWebsocket) WriteJSON(v interface{}) error {
	p.writeLock.Lock()
	defer p.writeLock.Unlock()
	w, err := p.conn.NextWriter(websocket.TextMessage)
	if err != nil {
		return err
	}
	if err := p.conn.SetWriteDeadline(mtime.Now().Add(writeWait)); err != nil {
		return err
	}
	err1 := codec.NewEncoder(w, &codec.JsonHandle{}).Encode(v)
	err2 := w.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// ReadJSON reads the next JSON-encoded message from the connection and stores
// it in the value pointed to by v.
func (p *pingingWebsocket) ReadJSON(v interface{}) error {
	p.readLock.Lock()
	defer p.readLock.Unlock()
	_, r, err := p.conn.NextReader()
	if err != nil {
		return err
	}
	err = codec.NewDecoder(r, &codec.JsonHandle{}).Decode(v)
	if err == io.EOF {
		// One value is expected in the message.
		err = io.ErrUnexpectedEOF
	}
	return err
}

// Close closes the connection
func (p *pingingWebsocket) Close() error {
	p.writeLock.Lock()
	defer p.writeLock.Unlock()
	p.pinger.Stop()
	return p.conn.Close()
}

// IsExpectedWSCloseError returns boolean indicating whether the error is a
// clean disconnection.
func IsExpectedWSCloseError(err error) bool {
	return err == io.EOF || err == io.ErrClosedPipe || websocket.IsCloseError(err,
		websocket.CloseNormalClosure,
		websocket.CloseGoingAway,
		websocket.CloseNoStatusReceived,
		websocket.CloseAbnormalClosure,
	)
}
