// +build linux darwin freebsd netbsd openbsd solaris dragonfly windows

package pb

import (
	"sync"
	"time"
)

// Create and start new pool with given bars
// You need call pool.Stop() after work
func StartPool(pbs ...*ProgressBar) (pool *Pool, err error) {
	pool = new(Pool)
	if err = pool.start(); err != nil {
		return
	}
	pool.add(pbs...)
	return
}

type Pool struct {
	RefreshRate time.Duration
	bars        []*ProgressBar
	quit        chan int
	finishOnce  sync.Once
}

func (p *Pool) add(pbs ...*ProgressBar) {
	for _, bar := range pbs {
		bar.ManualUpdate = true
		bar.NotPrint = true
		bar.Start()
		p.bars = append(p.bars, bar)
	}
}

func (p *Pool) start() (err error) {
	p.RefreshRate = DefaultRefreshRate
	quit, err := lockEcho()
	if err != nil {
		return
	}
	p.quit = make(chan int)
	go p.writer(quit)
	return
}

func (p *Pool) writer(finish chan int) {
	var first = true
	for {
		select {
		case <-time.After(p.RefreshRate):
			if p.print(first) {
				p.print(false)
				finish <- 1
				return
			}
			first = false
		case <-p.quit:
			finish <- 1
			return
		}
	}
}

// Restore terminal state and close pool
func (p *Pool) Stop() error {
	// Wait until one final refresh has passed.
	time.Sleep(p.RefreshRate)

	p.finishOnce.Do(func() {
		close(p.quit)
	})
	return unlockEcho()
}
