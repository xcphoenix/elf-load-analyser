package factory

import (
	"context"
	"sync"

	"github.com/phoenixxc/elf-load-analyser/pkg/core/state"

	"github.com/phoenixxc/elf-load-analyser/pkg/bcc"
	"github.com/phoenixxc/elf-load-analyser/pkg/log"
)

var (
	mutex           sync.Mutex
	finishedMonitor *bcc.Monitor
	factory         []*bcc.Monitor
)

func Register(monitor *bcc.Monitor) {
	if monitor.IsEnd() {
		if finishedMonitor != nil {
			log.Errorf("only one monitor can be set end")
		}
		finishedMonitor = monitor
		return
	}
	factory = append(factory, monitor)
}

// LoadMonitors ctx The run context, ctr control the proc when to stop
func LoadMonitors(param *bcc.PreParam) (p *Pool) {
	// 确保有且仅有一个 monitor 被设置为 end
	if finishedMonitor == nil {
		log.Errorf("no monitors be set end")
	}

	rootCtx := state.CreateRootContent()
	rootMonitorCtx, rootCancelFunc := context.WithCancel(rootCtx)

	ready := make(chan struct{})
	p = NewPool()
	ch := p.Chan()
	p.Init(rootMonitorCtx.Done())

	log.Info("Start load monitor....")
	for _, monitor := range factory {
		monitor := monitor
		if err := monitor.PreProcessing(param); err != nil {
			log.Errorf("Monitor %q pre processing error: %v", monitor.Name, err)
		}
		m := monitor.DoAction()
		go func() {
			defer func() {
				mutex.Unlock()
			}()
			monitor.Resolve(m, ch, ready, rootMonitorCtx.Done())
			mutex.Lock()
			m.Close()
		}()
	}

	if err := finishedMonitor.PreProcessing(param); err != nil {
		log.Errorf("Monitor %q pre processing error: %v", finishedMonitor.Name, err)
	}
	m := finishedMonitor.DoAction()
	go func() {
		defer func() {
			rootCancelFunc()
			mutex.Unlock()
		}()

		finishedMonitor.Resolve(m, ch, ready, rootCtx.Done())
		mutex.Lock()
		m.Close()
	}()

	for cnt := len(factory) + 1; cnt > 0; cnt-- {
		<-ready
	}
	log.Info("Load monitors ok")

	return
}
