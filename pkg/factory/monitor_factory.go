package factory

import (
	"context"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"reflect"
	"sync"

	"github.com/xcphoenix/elf-load-analyser/pkg/core/state"

	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
)

var (
	mutex         sync.Mutex
	registerMutex sync.Mutex

	factoryList []modules.ModuleFactory
	mmList      []*modules.MonitorModule
)

// Register 注册模块工厂类, mm 为空将被忽略
func Register(mm modules.ModuleFactory) {
	registerMutex.Lock()
	defer registerMutex.Unlock()

	if helper.IsNil(mm) {
		return
	}
	factoryList = append(factoryList, mm)
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
		if helper.IsNil(monitor) {
			continue
		}
		monitor := monitor
		idx := idx
		go func() {
			monitor.PreProcessing(param)
			m := monitor.DoAction()
			mmList[idx].Resolve(waitMonitorCtx, m, ch)
			mutex.Lock()
			m.Close()

			mutex.Unlock()
			wg.Done()
		}()
	}

	// 根模块处理
	go func() {
		lastMonitor.PreProcessing(param)
		m := lastMonitor.DoAction()
		mmList[lastIdx].Resolve(rootCtx, m, ch)
		mutex.Lock()
		m.Close()

		mutex.Unlock()
		// 根模块处理完毕，关闭以通知其他模块停止工作，
		waitCancelFunc()
		// 等待其他模块处理
		wg.Wait()
		// 处理结束，关闭
		rootCancelFunc()
	}()

	// 等待所有模块加载完毕
	p.WaitReady()
	log.Info("Load monitors ok")
	return
}

func initMm(param bcc.PreParam) ([]*bcc.Monitor, *bcc.Monitor, int, int) {
	var lastMonitor *bcc.Monitor
	monitors := make([]*bcc.Monitor, len(factoryList))

	var type2Factory = make(map[reflect.Type][]modules.ModuleFactory)
	for i := range factoryList {
		var factory = factoryList[i]
		var factoryType = reflect.TypeOf(factory)

		type2Factory[factoryType] = append(type2Factory[factoryType], factory)
	}

	var finalFactoryList = make([]modules.ModuleFactory, 0)
	for _, factoryList := range type2Factory {
		if len(factoryList) == 0 {
			continue
		}
		var mergeFunc = factoryList[0].Merge
		var afterMergedFactoryList = mergeFunc(factoryList)
		for i := range afterMergedFactoryList {
			if helper.IsNotNil(afterMergedFactoryList[i]) {
				finalFactoryList = append(finalFactoryList, afterMergedFactoryList[i])
			}
		}
	}

	mmList = make([]*modules.MonitorModule, len(finalFactoryList))

	cnt, lastIdx := 0, -1
	for idx, factory := range finalFactoryList {
		var mm = factory.Build()
		mmList[idx] = mm
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
