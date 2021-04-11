package factory

import (
	"context"
	"sync"

	"github.com/xcphoenix/elf-load-analyser/pkg/modules"

	"github.com/xcphoenix/elf-load-analyser/pkg/core/state"

	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
)

var (
	mutex         sync.Mutex
	registerMutex sync.Mutex
	factory       []*modules.MonitorModule
)

func Register(mm *modules.MonitorModule) {
	registerMutex.Lock()
	defer registerMutex.Unlock()

	factory = append(factory, mm)
}

// LoadMonitors ctx The run context, ctr control the proc when to stop
func LoadMonitors(param bcc.PreParam) (p *Pool) {
	registerMutex.Lock()
	defer registerMutex.Unlock()

	rootCtx := state.CreateRootContent()
	rootMonitorCtx, rootCancelFunc := context.WithCancel(rootCtx)

	ready := make(chan struct{})
	p = NewPool()
	ch := p.Chan()
	p.Init(rootMonitorCtx.Done())

	monitors, lastMonitor, lastIdx := initMm(param)
	cnt := 1

	log.Info("Start load monitor....")
	for idx, monitor := range monitors {
		if monitor == nil {
			continue
		}
		cnt++
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
		factory[lastIdx].Resolve(m, ch, ready, rootCtx.Done())
		mutex.Lock()
		m.Close()
	}()

	for ; cnt > 0; cnt-- {
		<-ready
	}
	log.Info("Load monitors ok")

	return
}

func initMm(param bcc.PreParam) ([]*bcc.Monitor, *bcc.Monitor, int) {
	var lastMonitor *bcc.Monitor
	monitors := make([]*bcc.Monitor, len(factory))

	cnt, lastIdx := 0, -1
	for idx, mm := range factory {
		tmpMonitor, end, skip := modules.ModuleInit(mm, param)
		if skip {
			continue
		}
		if end {
			if lastIdx >= 0 {
				log.Errorf("Only one monitor can be set end")
			}
			lastMonitor = tmpMonitor
			lastIdx = idx
			continue
		}
		monitors[idx] = tmpMonitor
		cnt++
	}

	if lastIdx < 0 {
		log.Errorf("No monitor be set end")
	}

	if cnt == 0 {
		log.Errorf("No invalid monitors")
	}

	return monitors, lastMonitor, lastIdx
}
