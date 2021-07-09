package perf

import (
	"context"
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"reflect"
	"strings"
	"sync"
	"time"

	bpf "github.com/iovisor/gobpf/bcc"
	log "github.com/sirupsen/logrus"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
)

// 内置标签
const (
	EndTag = "_END_" // 终止标志
)

var skipAnalyseData = data.NewOtherAnalyseData(data.InvalidStatus, "", nil)

type TableHandler func(data []byte) (*data.AnalyseData, error)

// TableCtx table context
type TableCtx struct {
	Name    string
	Monitor modules.MonitorModule

	loop    bool
	channel chan []byte
	handler TableHandler
	mark    map[string]struct{}
}

func (t TableCtx) IterOperator(op func(string)) {
	if len(t.mark) == 0 {
		return
	}
	for m := range t.mark {
		op(m)
	}
}

// PerfResolveMm BaseMonitorModule 的高级抽象，封装 table 和 resolve 的处理
type ResolveMm struct {
	*modules.MonitorModule
	tableIDs  []string
	table2Ctx map[string]*TableCtx
}

// NewPerfResolveMm 创建 Perf 模块
func NewPerfResolveMm(m *modules.MonitorModule) *ResolveMm {
	perfMm := &ResolveMm{
		MonitorModule: m,
		tableIDs:      []string{},
		table2Ctx:     map[string]*TableCtx{},
	}
	perfMm.MonitorModule.ModuleResolver = perfMm
	return perfMm
}

// Build 返回实际的模块
func (resolveMm *ResolveMm) Build() *modules.MonitorModule {
	return resolveMm.MonitorModule
}

// Merge 合并模块
func (resolveMm *ResolveMm) Merge(moduleList []modules.ModuleBuilder) []modules.ModuleBuilder {
	if len(moduleList) == 0 {
		return moduleList
	}

	var finalModules = make([]modules.ModuleBuilder, 0)
	var mergedPerfMm = NewPerfResolveMm(&modules.MonitorModule{
		Name:   "~",
		Source: "",
		Events: make([]*bcc.Event, 0),
	})
	for i := range moduleList {
		perfFactory, ok := moduleList[i].(*ResolveMm)
		if !ok {
			continue
		}

		// 标记为结束状态的模块以及延迟初始化的模块不进行合并
		if perfFactory.CanMerge && !perfFactory.IsEnd() && perfFactory.LazyInit == nil {
			mergedPerfMm.Source = strings.Join([]string{mergedPerfMm.Source, perfFactory.Source}, "\n")
			mergedPerfMm.Events = append(mergedPerfMm.Events, perfFactory.Events...)

			mergedPerfMm.tableIDs = append(mergedPerfMm.tableIDs, perfFactory.tableIDs...)
			for table, ctx := range perfFactory.table2Ctx {
				mergedPerfMm.table2Ctx[table] = ctx
			}
		} else {
			finalModules = append(finalModules, perfFactory)
		}
	}
	if len(finalModules) == len(moduleList) {
		return finalModules
	}
	return append(finalModules, mergedPerfMm)
}

// RegisterOnceTable 注册 table，仅执行一次操作
func (resolveMm *ResolveMm) RegisterOnceTable(name string, handler TableHandler) {
	resolveMm.RegisterTable(name, false, handler)
}

// RegisterTable 注册 table, 若 loop 为 true，返回对应的 chan，否则返回 nil
func (resolveMm *ResolveMm) RegisterTable(name string, loop bool, handler TableHandler) chan<- []byte {
	name = strings.TrimSpace(name)
	if handler == nil || len(name) == 0 {
		return nil
	}
	tableChannel := make(chan []byte)
	resolveMm.tableIDs = append(resolveMm.tableIDs, name)
	resolveMm.table2Ctx[name] = &TableCtx{
		Name:    fmt.Sprintf("%s%s", helper.IfElse(len(resolveMm.Name) == 0, "", resolveMm.Name+"@").(string), name),
		loop:    loop,
		channel: tableChannel,
		handler: handler,
		mark:    map[string]struct{}{},
		Monitor: *resolveMm.MonitorModule,
	}
	if !loop {
		return nil
	}
	return tableChannel
}

// SetMark 设置标记
func (resolveMm *ResolveMm) SetMark(name string, mk string) *ResolveMm {
	ctx, ok := resolveMm.table2Ctx[name]
	if !ok {
		return resolveMm
	}
	ctx.mark[mk] = struct{}{}
	return resolveMm
}

// IsEnd 模块是否被设置为终止模块
func (resolveMm *ResolveMm) IsEnd() bool {
	return resolveMm.MonitorModule.IsEnd
}

// Resolve 模块的解析策略
//nolint:funlen
func (resolveMm *ResolveMm) Resolve(ctx context.Context, m *bpf.Module, ch chan<- *data.AnalyseData) {
	var nameEntry = log.WithField("name", resolveMm.Name)

	if len(resolveMm.tableIDs) == 0 {
		nameEntry.Warnf("Monitor has no tables to resolve")
		ch <- skipAnalyseData
		return
	}

	var perfMaps = resolveMm.initPerfMaps(m)

	// 接受到终止请求、接受到终止请求后将未处理的数据处理完成，最终结束解析操作
	var terminating, terminated, end = ctx.Done(), make(chan struct{}), make(chan struct{})

	var tableNum = len(resolveMm.table2Ctx)
	var tableCnt = tableNum
	var cases, tableNames = buildBaseCases(resolveMm.table2Ctx, ch, terminating)

	var updateOnce sync.Once

	go func() {
	LOOP:
		for tableCnt > 0 {
			// 返回选择的索引、如果是 recv，返回 value 是否有效，ok 返回 false 表示 channel 被关闭
			var chosen, value, _ = reflect.Select(cases)
			switch {
			case chosen < tableNum:
				var tableCtx = resolveMm.table2Ctx[tableNames[chosen]]
				handleData(value.Bytes(), tableCtx, ch)

				if _, ok := tableCtx.mark[EndTag]; ok && resolveMm.IsEnd() {
					cases = updateCases(&updateOnce, cases, terminated)
				}

				if tableCtx.loop {
					continue
				}
				tableCnt--
			default:
				switch chosen - tableNum {
				case 0: // ready
				case 1:
					cases = updateCases(&updateOnce, cases, terminated)
				case 2:
					break LOOP
				case 3:
					close(terminated)
				}
			}
			clearCase(&cases[chosen])
		}
		close(end)
		for i := range cases {
			clearCase(&cases[i])
		}
	}()

	for _, perfMap := range perfMaps {
		perfMap.Start()
	}
	nameEntry.Debug("Monitor start work")

	<-end
	resolveMm.closePerfMaps(perfMaps)

	nameEntry.Debug("Monitor stop work")
}

func clearCase(scase *reflect.SelectCase) {
	scase.Chan = reflect.ValueOf(nil)
}

func buildBaseCases(table2Ctx map[string]*TableCtx, ready chan<- *data.AnalyseData,
	stop <-chan struct{}) ([]reflect.SelectCase, []string) {
	var ctxNum = len(table2Ctx)
	var cases = make([]reflect.SelectCase, ctxNum)
	var tableNames = make([]string, ctxNum)

	var idx = 0

	// bcc 事件
	for tableName, ctx := range table2Ctx {
		cases[idx] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ctx.channel),
		}
		tableNames[idx] = tableName
		idx++
	}
	// 模块就绪事件
	cases = append(cases, reflect.SelectCase{
		Dir:  reflect.SelectSend,
		Chan: reflect.ValueOf(ready),
		Send: reflect.ValueOf(skipAnalyseData),
	})
	// 模块终止事件
	cases = append(cases, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(stop),
	})
	return cases, tableNames
}

func updateCases(once *sync.Once, cases []reflect.SelectCase, terminated chan struct{}) []reflect.SelectCase {
	once.Do(func() {
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(terminated),
		})
		// 添加 default，当无其他事件时会被触发
		cases = append(cases, reflect.SelectCase{
			Dir: reflect.SelectDefault,
		})
	})
	return cases
}

// execTimeoutTask 执行任务，当任务超时时，放到后台去执行
func execTimeoutTask(name string, task func(), timeout time.Duration) {
	var channel = make(chan struct{})
	var once sync.Once
	go func() {
		task()
		once.Do(func() {
			close(channel)
		})
	}()
	select {
	case <-channel:
		return
	case <-time.After(timeout):
		once.Do(func() {
			close(channel)
		})
		log.Warnf("notice: task %q timeout", name)
		return
	}
}

// handleData 处理数据，解析为分析数据后，通过 chan 发送
// FIXME: 有时 PerfMap 不能被及时关闭
func handleData(d []byte, tableCtx *TableCtx, ch chan<- *data.AnalyseData) {
	var bpfTableEntry = log.WithField("table", tableCtx.Name)

	bpfTableEntry.Debugf("Resolve data")
	analyseData, err := tableCtx.handler(d)
	bpfTableEntry.Debugf("Receive data: %v", analyseData)

	if err != nil {
		bpfTableEntry.Warnf("Resolve error: %v", err)
	} else {
		// generate name
		if len(analyseData.Name) == 0 {
			analyseData.Name = tableCtx.Name
		}

		// fill mark for render
		tableCtx.IterOperator(func(s string) {
			analyseData.PutExtra(s, struct{}{})
		})

		ch <- analyseData
	}
}

// initPerfMaps 初始化 PerfMap
func (resolveMm *ResolveMm) initPerfMaps(m *bpf.Module) []*bpf.PerfMap {
	var idx = 0
	var perfMaps = make([]*bpf.PerfMap, len(resolveMm.tableIDs))
	for _, tableID := range resolveMm.tableIDs {
		var bpfTable = bpf.NewTable(m.TableId(tableID), m)
		perf, err := bpf.InitPerfMap(bpfTable, resolveMm.table2Ctx[tableID].channel, nil)
		if err != nil {
			log.Fatalf("Failed to init perf map for %q: %v", resolveMm.Name, err)
		}
		perfMaps[idx] = perf
		idx++
	}
	return perfMaps
}

func (resolveMm *ResolveMm) closePerfMaps(perfMaps []*bpf.PerfMap) {
	var perfMapCloseWg sync.WaitGroup
	perfMapCloseWg.Add(len(perfMaps))

	for idx, perfMap := range perfMaps {
		var perfMap, tableCtx = perfMap, resolveMm.tableIDs[idx]
		go func() {
			execTimeoutTask(tableCtx, func() {
				perfMap.Stop()
			}, time.Millisecond*500)
			perfMapCloseWg.Done()
		}()
	}

	perfMapCloseWg.Wait()
}
