package factory

import (
	"github.com/xcphoenix/elf-load-analyser/pkg/core/state"
	"sync"

	"github.com/xcphoenix/elf-load-analyser/pkg/data"
)

type Pool struct {
	once  sync.Once
	ch    chan *data.AnalyseData
	exit  chan struct{}
	data  []*data.AnalyseData
	ready chan struct{}
}

func NewPool() *Pool {
	return &Pool{
		ch:    make(chan *data.AnalyseData),
		exit:  make(chan struct{}),
		data:  make([]*data.AnalyseData, 0),
		ready: make(chan struct{}),
	}
}

func (p *Pool) Chan() chan<- *data.AnalyseData {
	return p.ch
}

// WaitReady 阻塞等待模块加载完毕
func (p *Pool) WaitReady() {
	<-p.ready
}

func (p *Pool) Data() []*data.AnalyseData {
	<-p.exit
	p.once.Do(func() {
		state.PushState(state.ProgramLoaded)
	})
	return p.data
}

// Init 初始化数据池，当 done 被关闭时，停止接收数据，waitCnt 表示数据接收前要等待的次数
func (p *Pool) Init(done <-chan struct{}, waitCnt int) {
	go func() {
		for {
			select {
			case d, ok := <-p.ch:
				if !ok {
					return
				}
				// 如果还未等待完成，丢弃数据，计数器减一
				if waitCnt > 0 {
					waitCnt--
					if waitCnt == 0 {
						close(p.ready)
					}
					continue
				}
				p.data = append(p.data, d)
			case <-done:
				close(p.ch)
				close(p.exit)
				return
			}
		}
	}()
}
