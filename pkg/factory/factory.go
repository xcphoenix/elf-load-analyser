package factory

import (
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"reflect"
	"sync"
)

type MonitorModuleFactory interface {
	// 注册模块
	Register(mm modules.ModuleBuilder)

	// 加载模块
	Load(context context.Context, pool *data.Pool, param bcc.PreParam)
}

// 合并模块
func mergeMonitorBuilders(builders []modules.ModuleBuilder) []modules.ModuleBuilder {
	if len(builders) == 0 {
		return make([]modules.ModuleBuilder, 0)
	}

	var type2Builder = make(map[reflect.Type][]modules.ModuleBuilder)

	// 依据类型分类
	for i := range builders {
		var builder = builders[i]
		var builderType = reflect.TypeOf(builder)

		type2Builder[builderType] = append(type2Builder[builderType], builder)
	}

	// 对每个类型进行合并操作
	var mergedBuilders = make([]modules.ModuleBuilder, 0)
	for _, builders := range type2Builder {
		if len(builders) == 0 {
			continue
		}
		var mergeFunc = builders[0].Merge
		var mergedResult = mergeFunc(builders)
		for i := range mergedResult {
			if helper.IsNotNil(mergedResult[i]) {
				mergedBuilders = append(mergedBuilders, mergedResult[i])
			}
		}
	}

	return mergedBuilders
}

// 初始化模块
//  param 环境参数信息
//  builders 监视器模块构建器数组
func initMonitorModules(param bcc.PreParam,
	builders []modules.ModuleBuilder) map[modules.MonitorModuleType][]*modules.MonitorModule {
	var type2MonitorModules = make(map[modules.MonitorModuleType][]*modules.MonitorModule, len(builders))

	for _, builder := range builders {
		var mm = builder.Build()
		var mmType = modules.ModuleInit(mm, param)
		type2MonitorModules[mmType] = append(type2MonitorModules[mmType], mm)
	}

	return type2MonitorModules
}

// 执行模块
//  context: 传递给 `modules.MonitorModule` Resolve 的上下文
//  param: 环境参数信息
//  mm: 执行的 `modules.MonitorModule`
//  mutex: 关闭模块时需要的锁
//  pool: 数据池
func executeMonitor(context context.Context,
	param bcc.PreParam, mm *modules.MonitorModule,
	mutex sync.Locker,
	pool *data.Pool) {
	var monitor = mm.Monitor()

	if helper.IsNil(monitor) {
		log.Fatalf("MonitorModule %q is not initialized", mm.Name)
	}

	monitor.PreProcessing(param)

	var m = monitor.DoAction()

	mm.Resolve(context, m, pool.Chan())

	mutex.Lock()
	m.Close()
	mutex.Unlock()
}
