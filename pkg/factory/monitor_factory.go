package factory

import (
	"context"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"sync"

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

// About memory: https://github.com/iovisor/bcc/issues/1949
// ---
// LoadMonitors ctx The run context, ctr control the proc when to stop
func LoadMonitors(param bcc.PreParam) (p *Pool) {
	registerMutex.Lock()
	defer registerMutex.Unlock()

	// 生命周期控制
	rootCtx := state.CreateRootContent()
	rootMonitorCtx, rootCancelFunc := context.WithCancel(rootCtx)
	waitMonitorCtx, waitCancelFunc := context.WithCancel(rootMonitorCtx)

	monitors, lastMonitor, lastIdx, cnt := initMm(param)

	p = NewPool()
	ch := p.Chan()
	// 当作为根的模块处理结束时，中止收集数据
	p.Init(rootMonitorCtx.Done(), cnt)

	wg := &sync.WaitGroup{}
	wg.Add(cnt - 1)

	log.Info("Start load monitor....")
	for idx, monitor := range monitors {
		if monitor == nil {
			continue
		}
		monitor := monitor
		idx := idx
		go func() {
			defer func() {
				mutex.Unlock()
				wg.Done()
			}()
			monitor.PreProcessing(param)
			m := monitor.DoAction()
			factory[idx].Resolve(waitMonitorCtx, m, ch)
			mutex.Lock()
			m.Close()
		}()
	}

	// 根模块处理
	go func() {
		defer func() {
			mutex.Unlock()
			// 根模块处理完毕，关闭以通知其他模块停止工作，
			waitCancelFunc()
			// 等待其他模块处理
			wg.Wait()
			// 处理结束，关闭
			rootCancelFunc()
		}()
		lastMonitor.PreProcessing(param)
		m := lastMonitor.DoAction()
		factory[lastIdx].Resolve(rootCtx, m, ch)
		mutex.Lock()
		m.Close()
	}()

	// 等待所有模块加载完毕
	p.WaitReady()
	log.Info("Load monitors ok")
	return
}

func initMm(param bcc.PreParam) ([]*bcc.Monitor, *bcc.Monitor, int, int) {
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
			cnt++
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
	return monitors, lastMonitor, lastIdx, cnt
}
