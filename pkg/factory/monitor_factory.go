package factory

import (
	"context"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"sync"

	"github.com/xcphoenix/elf-load-analyser/pkg/core/state"

	log "github.com/sirupsen/logrus"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
)

type DefaultMmFactory struct {
	mutex         sync.Mutex
	registerMutex sync.Mutex
	builders      []monitor.Builder
}

func NewDefaultMmFactory() *DefaultMmFactory {
	return &DefaultMmFactory{
		builders: make([]monitor.Builder, 0),
	}
}

func (factory *DefaultMmFactory) Register(mm monitor.Builder) {
	factory.registerMutex.Lock()
	defer factory.registerMutex.Unlock()

	if helper.IsNil(mm) {
		return
	}
	factory.builders = append(factory.builders, mm)
}

func (factory *DefaultMmFactory) Load(ctx context.Context, pool *data.Pool, param ebpf.PreParam) {
	factory.registerMutex.Lock()
	defer factory.registerMutex.Unlock()

	// 生命周期控制
	var rootCtx = createRootCtx(ctx)
	masterMonitorCtx, masterCancelFunc := context.WithCancel(rootCtx)
	slaveMonitorCtx, slaveCancelFunc := context.WithCancel(masterMonitorCtx)

	var masterMm, slaveMms = factory.initMm(param)
	var mmCnt = len(slaveMms) + 1

	go func() {
		<-masterMonitorCtx.Done()
		state.UpdateState(state.ProgramLoaded)
	}()
	// 当作为根的模块处理结束时，中止收集数据
	pool.InitPool(masterMonitorCtx.Done(), uint(mmCnt))

	var wg = &sync.WaitGroup{}
	wg.Add(mmCnt - 1)

	log.Info("Start to load monitor monitor")
	for _, mm := range slaveMms {
		var monitor = mm
		go func() {
			executeMonitor(slaveMonitorCtx, param, monitor, &factory.mutex, pool)
			wg.Done()
		}()
	}

	// 根模块处理
	go func() {
		executeMonitor(rootCtx, param, masterMm, &factory.mutex, pool)
		// 根模块处理完毕，关闭以通知其他模块停止工作，
		slaveCancelFunc()
		// 等待其他模块处理
		wg.Wait()
		// 处理结束，关闭
		masterCancelFunc()
	}()

	// 等待所有模块加载完毕
	pool.WaitReady()
	log.Info("Load monitor monitor finished")
}

func (factory *DefaultMmFactory) initMm(param ebpf.PreParam) (*monitor.Monitor, []*monitor.Monitor) {
	var mergedBuilders = mergeMonitorBuilders(factory.builders)
	var type2MonitorModules = initMonitorModules(param, mergedBuilders)

	var masterModules, slaveModules = type2MonitorModules[monitor.FinallyType], type2MonitorModules[monitor.NormalType]

	if helper.IsNil(slaveModules) {
		slaveModules = make([]*monitor.Monitor, 0)
	}
	if len(masterModules) != 1 {
		log.Fatalf("Can't find the only monitor module marked as the last")
	}

	return masterModules[0], slaveModules
}

func createRootCtx(ctx context.Context) context.Context {
	rootCtx, cancelFunc := context.WithCancel(ctx)
	state.RegisterHandler(state.Exit, func(_ error) error {
		cancelFunc()
		return nil
	})
	return rootCtx
}

var defaultMmFactory = NewDefaultMmFactory()

func Register(mm monitor.Builder) {
	defaultMmFactory.Register(mm)
}

func Load(ctx context.Context, pool *data.Pool, param ebpf.PreParam) {
	defaultMmFactory.Load(ctx, pool, param)
}
