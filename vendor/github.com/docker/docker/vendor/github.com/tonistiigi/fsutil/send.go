package fsutil

import (
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"
)

var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1<<10)
	},
}

type Stream interface {
	RecvMsg(interface{}) error
	SendMsg(m interface{}) error
	Context() context.Context
}

func Send(ctx context.Context, conn Stream, root string, opt *WalkOpt, progressCb func(int, bool)) error {
	s := &sender{
		conn:         &syncStream{Stream: conn},
		root:         root,
		opt:          opt,
		files:        make(map[uint32]string),
		progressCb:   progressCb,
		sendpipeline: make(chan *sendHandle, 128),
	}
	return s.run(ctx)
}

type sendHandle struct {
	id   uint32
	path string
}

type sender struct {
	conn            Stream
	opt             *WalkOpt
	root            string
	files           map[uint32]string
	mu              sync.RWMutex
	progressCb      func(int, bool)
	progressCurrent int
	sendpipeline    chan *sendHandle
}

func (s *sender) run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	defer s.updateProgress(0, true)

	g.Go(func() error {
		return s.walk(ctx)
	})

	for i := 0; i < 4; i++ {
		g.Go(func() error {
			for h := range s.sendpipeline {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				if err := s.sendFile(h); err != nil {
					return err
				}
			}
			return nil
		})
	}

	g.Go(func() error {
		defer close(s.sendpipeline)

		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			var p Packet
			if err := s.conn.RecvMsg(&p); err != nil {
				return err
			}
			switch p.Type {
			case PACKET_REQ:
				if err := s.queue(p.ID); err != nil {
					return err
				}
			case PACKET_FIN:
				return s.conn.SendMsg(&Packet{Type: PACKET_FIN})
			}
		}
	})

	return g.Wait()
}

func (s *sender) updateProgress(size int, last bool) {
	if s.progressCb != nil {
		s.progressCurrent += size
		s.progressCb(s.progressCurrent, last)
	}
}

func (s *sender) queue(id uint32) error {
	s.mu.Lock()
	p, ok := s.files[id]
	if !ok {
		s.mu.Unlock()
		return errors.Errorf("invalid file id %d", id)
	}
	delete(s.files, id)
	s.mu.Unlock()
	s.sendpipeline <- &sendHandle{id, p}
	return nil
}

func (s *sender) sendFile(h *sendHandle) error {
	f, err := os.Open(filepath.Join(s.root, h.path))
	if err == nil {
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		if _, err := io.CopyBuffer(&fileSender{sender: s, id: h.id}, f, buf); err != nil {
			return err
		}
	}
	return s.conn.SendMsg(&Packet{ID: h.id, Type: PACKET_DATA})
}

func (s *sender) walk(ctx context.Context) error {
	var i uint32 = 0
	err := Walk(ctx, s.root, s.opt, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		stat, ok := fi.Sys().(*Stat)
		if !ok {
			return errors.Wrapf(err, "invalid fileinfo without stat info: %s", path)
		}

		p := &Packet{
			Type: PACKET_STAT,
			Stat: stat,
		}
		if fileCanRequestData(os.FileMode(stat.Mode)) {
			s.mu.Lock()
			s.files[i] = stat.Path
			s.mu.Unlock()
		}
		i++
		s.updateProgress(p.Size(), false)
		return errors.Wrapf(s.conn.SendMsg(p), "failed to send stat %s", path)
	})
	if err != nil {
		return err
	}
	return errors.Wrapf(s.conn.SendMsg(&Packet{Type: PACKET_STAT}), "failed to send last stat")
}

func fileCanRequestData(m os.FileMode) bool {
	// avoid updating this function as it needs to match between sender/receiver.
	// version if needed
	return m&os.ModeType == 0
}

type fileSender struct {
	sender *sender
	id     uint32
}

func (fs *fileSender) Write(dt []byte) (int, error) {
	if len(dt) == 0 {
		return 0, nil
	}
	p := &Packet{Type: PACKET_DATA, ID: fs.id, Data: dt}
	if err := fs.sender.conn.SendMsg(p); err != nil {
		return 0, err
	}
	fs.sender.updateProgress(p.Size(), false)
	return len(dt), nil
}

type syncStream struct {
	Stream
	mu sync.Mutex
}

func (ss *syncStream) SendMsg(m interface{}) error {
	ss.mu.Lock()
	err := ss.Stream.SendMsg(m)
	ss.mu.Unlock()
	return err
}
