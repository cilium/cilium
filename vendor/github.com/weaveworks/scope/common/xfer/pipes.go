package xfer

import (
	"io"
	"sync"

	"github.com/gorilla/websocket"
)

// Pipe is a bi-directional channel from someone thing in the probe
// to the UI.
type Pipe interface {
	Ends() (io.ReadWriter, io.ReadWriter)
	CopyToWebsocket(io.ReadWriter, Websocket) error

	Close() error
	Closed() bool
	OnClose(func())
}

type pipe struct {
	mtx             sync.Mutex
	wg              sync.WaitGroup
	port, starboard io.ReadWriter
	closers         []io.Closer
	quit            chan struct{}
	closed          bool
	onClose         func()
}

// NewPipeFromEnds makes a new pipe specifying its ends
func NewPipeFromEnds(local io.ReadWriter, remote io.ReadWriter) Pipe {
	return &pipe{
		port:      local,
		starboard: remote,
		quit:      make(chan struct{}),
	}
}

// NewPipe makes a new pipe
func NewPipe() Pipe {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return &pipe{
		port: struct {
			io.Reader
			io.Writer
		}{
			r1, w2,
		},
		starboard: struct {
			io.Reader
			io.Writer
		}{
			r2, w1,
		},
		closers: []io.Closer{
			r1, r2, w1, w2,
		},
		quit: make(chan struct{}),
	}
}

func (p *pipe) Ends() (io.ReadWriter, io.ReadWriter) {
	return p.port, p.starboard
}

func (p *pipe) Close() error {
	p.mtx.Lock()
	var onClose func()
	if !p.closed {
		p.closed = true
		close(p.quit)
		for _, c := range p.closers {
			c.Close()
		}
		onClose = p.onClose
	}
	p.mtx.Unlock()
	p.wg.Wait()

	// Don't run onClose under lock.
	if onClose != nil {
		onClose()
	}
	return nil
}

func (p *pipe) Closed() bool {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	return p.closed
}

func (p *pipe) OnClose(f func()) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.onClose = f
}

// CopyToWebsocket copies pipe data to/from a websocket.  It blocks.
func (p *pipe) CopyToWebsocket(end io.ReadWriter, conn Websocket) error {
	p.mtx.Lock()
	if p.closed {
		p.mtx.Unlock()
		return nil
	}
	p.wg.Add(1)
	p.mtx.Unlock()
	defer p.wg.Done()

	// The goroutines below both post their errors to the channel, but if you close()
	// the pipe before any errors then the pipe may not get read from. Therefore it
	// needs up to 2 slots free.
	errors := make(chan error, 2)

	// Read-from-UI loop
	go func() {
		for {
			_, buf, err := conn.ReadMessage() // TODO type should be binary message
			if err != nil {
				errors <- err
				return
			}

			if p.Closed() {
				return
			}

			if _, err := end.Write(buf); err != nil {
				errors <- err
				return
			}
		}
	}()

	// Write-to-UI loop
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := end.Read(buf)
			if err != nil {
				errors <- err
				return
			}

			if p.Closed() {
				return
			}

			if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				errors <- err
				return
			}
		}
	}()

	// block until one of the goroutines exits
	// this convoluted mechanism is to ensure we only close the websocket once.
	select {
	case err := <-errors:
		return err
	case <-p.quit:
		return nil
	}
}
