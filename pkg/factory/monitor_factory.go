package factory

import (
	"context"
	"sync"

	"github.com/phoenixxc/elf-load-analyser/pkg/modules"

	"github.com/phoenixxc/elf-load-analyser/pkg/core/state"

	"github.com/phoenixxc/elf-load-analyser/pkg/bcc"
	"github.com/phoenixxc/elf-load-analyser/pkg/log"
)

var (
	mutex           sync.Mutex
	registerMutex   sync.Mutex
	finishedMonitor *modules.MonitorModule
	factory         []*modules.MonitorModule
)

func Register(mm *modules.MonitorModule) {
	registerMutex.Lock()
	defer registerMutex.Unlock()

	if mm.IsEnd {
		if finishedMonitor != nil {
			log.Errorf("only one monitor can be set end")
		}
		finishedMonitor = mm
		return
	}
	factory = append(factory, mm)
}

// LoadMonitors ctx The run context, ctr control the proc when to stop
func LoadMonitors(param bcc.PreParam) (p *Pool) {
	registerMutex.Lock()
	defer registerMutex.Unlock()

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

	monitors, lastMonitor := initMm(param)

	log.Info("Start load monitor....")
	for idx, monitor := range monitors {
		monitor := monitor
		monitor.PreProcessing(param)
		m := monitor.DoAction()
		idx := idx
		go func() {
			defer mutex.Unlock()
			factory[idx].Resolve(m, ch, ready, rootMonitorCtx.Done())
			mutex.Lock()
			m.Close()
		}()
	}

	lastMonitor.PreProcessing(param)
	m := lastMonitor.DoAction()
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

func initMm(param bcc.PreParam) ([]*bcc.Monitor, *bcc.Monitor) {
	monitors := make([]*bcc.Monitor, len(factory))
	for idx, mm := range factory {
		monitors[idx] = modules.ModuleInit(mm, param)
	}
	lastMonitor := modules.ModuleInit(finishedMonitor, param)
	return monitors, lastMonitor
}
