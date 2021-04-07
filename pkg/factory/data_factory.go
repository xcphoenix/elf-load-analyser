package factory

import (
	"sort"
	"sync"
	"time"

	"github.com/phoenixxc/elf-load-analyser/pkg/data"
	"github.com/phoenixxc/elf-load-analyser/pkg/state"
)

type Pool struct {
	mu    sync.Mutex
	order bool
	ch    chan *data.AnalyseData
	exit  chan struct{}
	data  []*data.AnalyseData
}

func (p *Pool) Len() int {
	return len(p.data)
}

func (p *Pool) Less(i, j int) bool {
	return time.Time(p.data[i].XTime).Before(time.Time(p.data[j].XTime))
}

func (p *Pool) Swap(i, j int) {
	d := p.data
	d[i], d[j] = d[j], d[i]
}

func NewPool() *Pool {
	return &Pool{ch: make(chan *data.AnalyseData), exit: make(chan struct{}), data: make([]*data.AnalyseData, 0), order: false}
}

func (p *Pool) Chan() chan<- *data.AnalyseData {
	return p.ch
}

func (p *Pool) Data() []*data.AnalyseData {
	<-p.exit
	if !p.order {
		p.mu.Lock()
		if !p.order {
			sort.Sort(p)
			p.order = true
		}
		state.PushState(state.ProgramLoaded)
		p.mu.Unlock()
	}
	return p.data
}

func (p *Pool) Close() {
	close(p.ch)
	close(p.exit)
}

func (p *Pool) Init() {
	go func() {
	loop:
		for {
			select {
			case <-p.exit:
				break loop
			case d, ok := <-p.ch:
				if !ok {
					break loop
				}
				p.data = append(p.data, d)
			}
		}
	}()
}
