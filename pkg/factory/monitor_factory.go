package factory

import (
	"context"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"sync"

	"github.com/xcphoenix/elf-load-analyser/pkg/core/state"

	log "github.com/sirupsen/logrus"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
)

type DefaultMmFactory struct {
	mutex         sync.Mutex
	registerMutex sync.Mutex
	builders      []modules.ModuleBuilder
}

func NewDefaultMmFactory() *DefaultMmFactory {
	return &DefaultMmFactory{
		builders: make([]modules.ModuleBuilder, 0),
	}
}

func (factory *DefaultMmFactory) Register(mm modules.ModuleBuilder) {
	factory.registerMutex.Lock()
	defer factory.registerMutex.Unlock()

	if helper.IsNil(mm) {
		return
	}
	factory.builders = append(factory.builders, mm)
}

func (factory *DefaultMmFactory) Load(ctx context.Context, pool *data.Pool, param bcc.PreParam) {
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
	pool.InitPool(masterMonitorCtx.Done(), mmCnt)

	var wg = &sync.WaitGroup{}
	wg.Add(mmCnt - 1)

	log.Info("Start to load monitor modules")
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
	log.Info("Load monitor modules finished")
}

func (factory *DefaultMmFactory) initMm(param bcc.PreParam) (*modules.MonitorModule, []*modules.MonitorModule) {
	var mergedBuilders = mergeMonitorBuilders(factory.builders)
	var type2MonitorModules = initMonitorModules(param, mergedBuilders)

	var masterModules, slaveModules = type2MonitorModules[modules.FinallyType], type2MonitorModules[modules.NormalType]

	if helper.IsNil(slaveModules) {
		slaveModules = make([]*modules.MonitorModule, 0)
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

func Register(mm modules.ModuleBuilder) {
	defaultMmFactory.Register(mm)
}

func Load(ctx context.Context, pool *data.Pool, param bcc.PreParam) {
	defaultMmFactory.Load(ctx, pool, param)
}
