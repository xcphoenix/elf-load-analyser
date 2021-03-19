package factory

import (
	data2 "github.com/phoenixxc/elf-load-analyser/pkg/data"
	"sort"
	"sync"
	"time"
)

type Pool struct {
	mu    sync.Mutex
	order bool
	ch    chan *data2.AnalyseData
	exit  chan struct{}
	data  []*data2.AnalyseData
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
	return &Pool{ch: make(chan *data2.AnalyseData), exit: make(chan struct{}), data: make([]*data2.AnalyseData, 0), order: false}
}

func (p *Pool) Chan() chan<- *data2.AnalyseData {
	return p.ch
}

func (p *Pool) Data() []*data2.AnalyseData {
	<-p.exit
	if !p.order {
		p.mu.Lock()
		if !p.order {
			sort.Sort(p)
			p.order = true
		}
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
			case data, ok := <-p.ch:
				if !ok {
					break loop
				}
				p.data = append(p.data, data)
			}
		}
	}()
}
