package factory

import (
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"reflect"
	"sync"
	"time"
)

type MonitorModuleFactory interface {
	// 注册模块
	Register(mm monitor.Builder)

	// 加载模块
	Load(context context.Context, pool *data.Pool, param ebpf.PreParam)
}

// 合并模块
func mergeMonitorBuilders(builders []monitor.Builder) []monitor.Builder {
	if len(builders) == 0 {
		return make([]monitor.Builder, 0)
	}

	var type2Builder = make(map[reflect.Type][]monitor.Builder)

	// 依据类型分类
	for i := range builders {
		var builder = builders[i]
		var builderType = reflect.TypeOf(builder)

		type2Builder[builderType] = append(type2Builder[builderType], builder)
	}

	// 对每个类型进行合并操作
	var mergedBuilders = make([]monitor.Builder, 0)
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
func initMonitorModules(param ebpf.PreParam,
	builders []monitor.Builder) map[monitor.Type][]*monitor.Monitor {
	var type2MonitorModules = make(map[monitor.Type][]*monitor.Monitor, len(builders))

	for _, builder := range builders {
		var mm = builder.Build()
		var mmType = monitor.InitMonitor(mm, param)
		type2MonitorModules[mmType] = append(type2MonitorModules[mmType], mm)
	}

	return type2MonitorModules
}

// 执行模块
//  context: 传递给 `monitor.Monitor` Resolve 的上下文
//  param: 环境参数信息
//  mm: 执行的 `monitor.Monitor`
//  mutex: 关闭模块时需要的锁
//  pool: 数据池
func executeMonitor(context context.Context,
	param ebpf.PreParam, mm *monitor.Monitor,
	mutex sync.Locker,
	pool *data.Pool) {
	var module = mm.Module()

	if helper.IsNil(module) {
		log.Fatalf("Module %q is not initialized", mm.Name)
	}

	module.PreProcessing(param)

	var m = module.DoAction()

	mm.Resolve(context, m, pool.Chan())

	go func() {
		<-time.After(time.Millisecond * 600)
		mutex.Lock()
		m.Close()
		mutex.Unlock()
	}()
}
