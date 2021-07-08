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

const EndFlag = "_END_"

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
	tableIds  []string
	table2Ctx map[string]*TableCtx
}

// NewPerfResolveMm 创建 Perf 模块
func NewPerfResolveMm(m *modules.MonitorModule) *ResolveMm {
	perfMm := &ResolveMm{
		MonitorModule: m,
		tableIds:      []string{},
		table2Ctx:     map[string]*TableCtx{},
	}
	perfMm.MonitorModule.ModuleResolver = perfMm
	return perfMm
}

// Build 返回实际的模块
func (p *ResolveMm) Build() *modules.MonitorModule {
	return p.MonitorModule
}

// Merge 合并模块
func (p *ResolveMm) Merge(moduleList []modules.ModuleBuilder) []modules.ModuleBuilder {
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

			mergedPerfMm.tableIds = append(mergedPerfMm.tableIds, perfFactory.tableIds...)
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
func (p *ResolveMm) RegisterOnceTable(name string, handler TableHandler) {
	p.RegisterTable(name, false, handler)
}

// RegisterTable 注册 table, 若 loop 为 true，返回对应的 chan，否则返回 nil
func (p *ResolveMm) RegisterTable(name string, loop bool, handler TableHandler) chan<- []byte {
	name = strings.TrimSpace(name)
	if handler == nil || len(name) == 0 {
		return nil
	}
	tableChannel := make(chan []byte)
	p.tableIds = append(p.tableIds, name)
	p.table2Ctx[name] = &TableCtx{
		Name:    fmt.Sprintf("%s%s", helper.IfElse(len(p.Name) == 0, "", p.Name+"@").(string), name),
		loop:    loop,
		channel: tableChannel,
		handler: handler,
		mark:    map[string]struct{}{},
		Monitor: *p.MonitorModule,
	}
	if !loop {
		return nil
	}
	return tableChannel
}

// SetMark 设置标记
func (p *ResolveMm) SetMark(name string, mk string) *ResolveMm {
	ctx, ok := p.table2Ctx[name]
	if !ok {
		return p
	}
	ctx.mark[mk] = struct{}{}
	return p
}

// IsEnd 模块是否被设置为终止模块
func (p *ResolveMm) IsEnd() bool {
	return p.MonitorModule.IsEnd
}

//nolint:funlen
// Resolve 模块的解析策略
func (p *ResolveMm) Resolve(ctx context.Context, m *bpf.Module, ch chan<- *data.AnalyseData) {
	if len(p.tableIds) == 0 {
		log.Warnf("Name %q without event", p.Name)
		readyNotify(ch)
		return
	}

	perfMaps := initPerMaps(m, p)
	finish := make(chan struct{})

	startEnd := make(chan struct{})
	endNow := make(chan struct{})

	chCnt := len(p.table2Ctx)
	cnt := chCnt + 3 // ready stop startStop
	remaining := cnt
	cases, tableNames := buildSelectCase(cnt, p.table2Ctx, ch, ctx.Done(), endNow)

	lastRemain := 0
	if p.IsEnd() {
		lastRemain++
	}
	wg := &sync.WaitGroup{}

	go func() {
		<-startEnd
		<-time.After(500 * time.Millisecond)
		endNow <- struct{}{}
	}()

	go func() {
		defer func() {
			wg.Wait()
			// clear
			for i := range cases {
				cases[i].Chan = reflect.ValueOf(nil)
			}
			close(finish)
		}()

		for remaining > lastRemain {
			// 返回选择的索引、如果是 recv，返回 value 是否有效，ok 返回 false 表示 channel 被关闭
			chosen, value, ok := reflect.Select(cases)
			//goland:noinspection GoLinterLocal
			if value.IsValid() && ok && chosen < len(tableNames) {
				tName := tableNames[chosen]
				tableCtx := p.table2Ctx[tName]
				d := value.Bytes()
				wg.Add(1)
				go func() {
					defer wg.Done()
					dataProcessing(d, tableCtx, ch)
				}()
				if _, ok := tableCtx.mark[EndFlag]; ok && p.IsEnd() {
					startEnd <- struct{}{}
				} else if tableCtx.loop {
					continue
				}
			} else if chosen == chCnt+1 {
				// 接收到终止信号
				log.Debugf("Name %q exit", p.Name)
				startEnd <- struct{}{}
			} else if chosen == chCnt+2 {
				break
			}
			cases[chosen].Chan = reflect.ValueOf(nil)
			remaining--
		}
	}()

	for _, perfMap := range perfMaps {
		perfMap.Start()
	}
	log.Infof("Monitor module %s start...", p.Name)
	<-finish
	// FIXME cannot stop on sometimes
	go func() {
		for idx, perfMap := range perfMaps {
			blockTaskTimeout(p.tableIds[idx], func() { perfMap.Stop() }, time.Millisecond*500)
		}
	}()
	log.Infof("Monitor module %s stop", p.Name)
}

func readyNotify(ch chan<- *data.AnalyseData) {
	ch <- data.NewOtherAnalyseData(data.InvalidStatus, "", nil)
}

func blockTaskTimeout(name string, task func(), timeout time.Duration) {
	ch := make(chan struct{})
	go func() {
		task()
		close(ch)
	}()
	select {
	case <-ch:
		return
	case <-time.After(timeout):
		log.Infof("notice: task %q timeout", name)
		return
	}
}

func dataProcessing(d []byte, tableCtx *TableCtx, ch chan<- *data.AnalyseData) {
	log.Infof("Resolve %q...", tableCtx.Name)
	analyseData, err := tableCtx.handler(d)
	log.Debugf("Receive data from %q, %v", tableCtx.Name, analyseData)

	if err != nil {
		log.Warnf("Event %q resolve error: %v", tableCtx.Name, err)
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

func buildSelectCase(cnt int, table2Ctx map[string]*TableCtx, ready chan<- *data.AnalyseData,
	stop <-chan struct{}, endNow <-chan struct{}) ([]reflect.SelectCase, []string) {
	chCnt := len(table2Ctx)
	cases := make([]reflect.SelectCase, cnt)
	tableNames := make([]string, chCnt)

	i := 0
	// receive bcc perf_submit
	for t, c := range table2Ctx {
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(c.channel)}
		tableNames[i] = t
		i++
	}
	// send this module is ok
	cases[chCnt] = reflect.SelectCase{
		Dir:  reflect.SelectSend,
		Chan: reflect.ValueOf(ready),
		Send: reflect.ValueOf(data.NewOtherAnalyseData(data.InvalidStatus, "", nil)),
	}
	cases[chCnt+1] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(stop)}
	// 收到停止信号后延迟一段时间
	cases[chCnt+2] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(endNow)}
	return cases, tableNames
}

func initPerMaps(m *bpf.Module, p *ResolveMm) []*bpf.PerfMap {
	perI := 0
	perfMaps := make([]*bpf.PerfMap, len(p.tableIds))
	for _, table := range p.tableIds {
		t := bpf.NewTable(m.TableId(table), m)
		perf, err := bpf.InitPerfMap(t, p.table2Ctx[table].channel, nil)
		if err != nil {
			log.Fatalf("(%s, %s) Failed to init perf map: %v", p.Name, "events", err)
		}
		perfMaps[perI] = perf
		perI++
	}
	return perfMaps
}
