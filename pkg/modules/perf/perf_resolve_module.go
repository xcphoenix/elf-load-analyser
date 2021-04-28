package perf

import (
	"context"
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"reflect"
	"strings"
	"sync"
	"time"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
)

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

// Mm 返回实际的模块
func (p *ResolveMm) Mm() *modules.MonitorModule {
	return p.MonitorModule
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
		Name:    fmt.Sprintf("%s@%s", p.Monitor, name),
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
		log.Warnf("Monitor %q without event", p.Monitor)
		readyNotify(ch)
		return
	}

	perfMaps := initPerMaps(m, p)
	finish := make(chan struct{})

	chCnt := len(p.table2Ctx)
	cnt := chCnt + 2
	remaining := cnt
	cases, tableNames := buildSelectCase(cnt, p.table2Ctx, ch, ctx.Done())

	lastRemain := 0
	if p.IsEnd() {
		lastRemain++
	}
	wg := &sync.WaitGroup{}

	go func() {
		defer func() {
			wg.Wait()
			close(finish)
		}()

		for remaining > lastRemain {
			// 返回选择的索引、如果是 recv，返回 value 是否有效，ok 返回 false 表示 channel 被关闭
			chosen, value, ok := reflect.Select(cases)
			if value.IsValid() && ok {
				tName := tableNames[chosen]
				tableCtx := p.table2Ctx[tName]

				d := value.Bytes()
				wg.Add(1)
				go func() {
					defer wg.Done()
					dataProcessing(d, tableCtx, ch)
				}()
				if tableCtx.loop {
					continue
				}
			} else if chosen == chCnt+1 {
				// 接收到终止信号
				log.Debugf("Monitor %q exit", p.Monitor)
				break
			}
			cases[chosen].Chan = reflect.ValueOf(nil)
			remaining--
		}
	}()

	for _, perfMap := range perfMaps {
		perfMap.Start()
	}
	log.Infof("Monitor %s start...", p.Monitor)
	<-finish
	// FIXME cannot stop on sometimes
	for idx, perfMap := range perfMaps {
		blockTaskTimeout(p.tableIds[idx], func() { perfMap.Stop() }, time.Millisecond*500*2)
	}
	log.Infof("Monitor %s stop", p.Monitor)
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
		log.Warnf("task %q timeout", name)
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
	stop <-chan struct{}) ([]reflect.SelectCase, []string) {
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
	if idx := chCnt + 1; idx < cnt {
		cases[idx] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(stop)}
	}
	return cases, tableNames
}

func initPerMaps(m *bpf.Module, p *ResolveMm) []*bpf.PerfMap {
	perI := 0
	perfMaps := make([]*bpf.PerfMap, len(p.tableIds))
	for _, table := range p.tableIds {
		t := bpf.NewTable(m.TableId(table), m)
		perf, err := bpf.InitPerfMap(t, p.table2Ctx[table].channel, nil)
		if err != nil {
			log.Errorf("(%s, %s) Failed to init perf map: %v", p.Monitor, "events", err)
		}
		perfMaps[perI] = perf
		perI++
	}
	return perfMaps
}