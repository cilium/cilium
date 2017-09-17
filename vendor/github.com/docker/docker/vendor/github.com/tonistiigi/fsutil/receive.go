// +build linux windows

package fsutil

import (
	"io"
	"os"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"
)

func Receive(ctx context.Context, conn Stream, dest string, notifyHashed ChangeFunc) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := &receiver{
		conn:         &syncStream{Stream: conn},
		dest:         dest,
		files:        make(map[string]uint32),
		pipes:        make(map[uint32]io.WriteCloser),
		notifyHashed: notifyHashed,
	}
	return r.run(ctx)
}

type receiver struct {
	dest    string
	conn    Stream
	files   map[string]uint32
	pipes   map[uint32]io.WriteCloser
	mu      sync.RWMutex
	muPipes sync.RWMutex

	notifyHashed   ChangeFunc
	orderValidator Validator
	hlValidator    Hardlinks
}

type dynamicWalker struct {
	walkChan chan *currentPath
	closed   bool
}

func newDynamicWalker() *dynamicWalker {
	return &dynamicWalker{
		walkChan: make(chan *currentPath, 128),
	}
}

func (w *dynamicWalker) update(p *currentPath) error {
	if w.closed {
		return errors.New("walker is closed")
	}
	if p == nil {
		close(w.walkChan)
		return nil
	}
	w.walkChan <- p
	return nil
}

func (w *dynamicWalker) fill(ctx context.Context, pathC chan<- *currentPath) error {
	for {
		select {
		case p, ok := <-w.walkChan:
			if !ok {
				return nil
			}
			pathC <- p
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (r *receiver) run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	dw, err := NewDiskWriter(ctx, r.dest, DiskWriterOpt{
		AsyncDataCb: r.asyncDataFunc,
		NotifyCb:    r.notifyHashed,
	})
	if err != nil {
		return err
	}

	w := newDynamicWalker()

	g.Go(func() error {
		err := doubleWalkDiff(ctx, dw.HandleChange, GetWalkerFn(r.dest), w.fill)
		if err != nil {
			return err
		}
		if err := dw.Wait(ctx); err != nil {
			return err
		}
		r.conn.SendMsg(&Packet{Type: PACKET_FIN})
		return nil
	})

	g.Go(func() error {
		var i uint32 = 0

		var p Packet
		for {
			p = Packet{Data: p.Data[:0]}
			if err := r.conn.RecvMsg(&p); err != nil {
				return err
			}
			switch p.Type {
			case PACKET_STAT:
				if p.Stat == nil {
					if err := w.update(nil); err != nil {
						return err
					}
					break
				}
				if fileCanRequestData(os.FileMode(p.Stat.Mode)) {
					r.mu.Lock()
					r.files[p.Stat.Path] = i
					r.mu.Unlock()
				}
				i++
				cp := &currentPath{path: p.Stat.Path, f: &StatInfo{p.Stat}}
				if err := r.orderValidator.HandleChange(ChangeKindAdd, cp.path, cp.f, nil); err != nil {
					return err
				}
				if err := r.hlValidator.HandleChange(ChangeKindAdd, cp.path, cp.f, nil); err != nil {
					return err
				}
				if err := w.update(cp); err != nil {
					return err
				}
			case PACKET_DATA:
				r.muPipes.Lock()
				pw, ok := r.pipes[p.ID]
				r.muPipes.Unlock()
				if !ok {
					return errors.Errorf("invalid file request %s", p.ID)
				}
				if len(p.Data) == 0 {
					if err := pw.Close(); err != nil {
						return err
					}
				} else {
					if _, err := pw.Write(p.Data); err != nil {
						return err
					}
				}
			case PACKET_FIN:
				return nil
			}
		}
	})
	return g.Wait()
}

func (r *receiver) asyncDataFunc(ctx context.Context, p string, wc io.WriteCloser) error {
	r.mu.Lock()
	id, ok := r.files[p]
	if !ok {
		r.mu.Unlock()
		return errors.Errorf("invalid file request %s", p)
	}
	delete(r.files, p)
	r.mu.Unlock()

	wwc := newWrappedWriteCloser(wc)
	r.muPipes.Lock()
	r.pipes[id] = wwc
	r.muPipes.Unlock()
	if err := r.conn.SendMsg(&Packet{Type: PACKET_REQ, ID: id}); err != nil {
		return err
	}
	err := wwc.Wait(ctx)
	r.muPipes.Lock()
	delete(r.pipes, id)
	r.muPipes.Unlock()
	return err
}

type wrappedWriteCloser struct {
	io.WriteCloser
	err  error
	once sync.Once
	done chan struct{}
}

func newWrappedWriteCloser(wc io.WriteCloser) *wrappedWriteCloser {
	return &wrappedWriteCloser{WriteCloser: wc, done: make(chan struct{})}
}

func (w *wrappedWriteCloser) Close() error {
	w.err = w.WriteCloser.Close()
	w.once.Do(func() { close(w.done) })
	return w.err
}

func (w *wrappedWriteCloser) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.done:
		return w.err
	}
}
