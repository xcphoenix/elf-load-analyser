package modules

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
)

var (
	mutex              sync.Once
	registeredEnhancer = make(map[string]Enhancer)
)

func RegisteredEnhancer(name string, e Enhancer) {
	registeredEnhancer[name] = e
}

type TableHandler func(data []byte) (*data.AnalyseData, error)

// TableCtx table context
type TableCtx struct {
	Name    string
	Monitor MonitorModule

	loop    bool
	channel chan []byte
	handler TableHandler
	mark    map[string]struct{}
}

func (t *TableCtx) IsMark(mk string) bool {
	_, ok := t.mark[mk]
	return ok
}

// Enhancer 增强器，只能做一些简单的流程协调操作
type Enhancer interface {
	PreHandle(tCtx *TableCtx)
	AfterHandle(tCtx *TableCtx, aData *data.AnalyseData, err error) (*data.AnalyseData, error)
}

// PerfResolveMm BaseMonitorModule 的高级抽象，封装 table 和 resolve 的处理
type PerfResolveMm struct {
	*MonitorModule
	tableIds  []string
	table2Ctx map[string]*TableCtx
}

func NewPerfResolveMm(m *MonitorModule) *PerfResolveMm {
	perfMm := &PerfResolveMm{
		MonitorModule: m,
		tableIds:      []string{},
		table2Ctx:     map[string]*TableCtx{},
	}
	perfMm.MonitorModule.ModuleResolver = perfMm
	return perfMm
}

func (p *PerfResolveMm) Mm() *MonitorModule {
	return p.MonitorModule
}

// RegisterOnceTable 注册 table，仅执行一次操作
func (p *PerfResolveMm) RegisterOnceTable(name string, handler TableHandler) {
	p.RegisterTable(name, false, handler)
}

// RegisterTable 注册 table, 若 loop 为 true，返回对应的 chan，否则返回 nil
func (p *PerfResolveMm) RegisterTable(name string, loop bool, handler TableHandler) chan<- []byte {
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

func (p *PerfResolveMm) SetMark(name string, mk string) *PerfResolveMm {
	ctx, ok := p.table2Ctx[name]
	if !ok {
		return p
	}
	ctx.mark[mk] = struct{}{}
	return p
}

func (p *PerfResolveMm) IsEnd() bool {
	return p.MonitorModule.IsEnd
}

func readyNotify(ch chan<- *data.AnalyseData) {
	ch <- data.NewErrAnalyseData("", data.Invalid, "")
}

//nolint:funlen
func (p *PerfResolveMm) Resolve(ctx context.Context, m *bpf.Module, ch chan<- *data.AnalyseData) {
	if len(p.tableIds) == 0 {
		log.Warnf("Monitor %q without event", p.Monitor)
		readyNotify(ch)
		return
	}
	showRegisteredEnhancer()

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
		blockTaskTimeout(p.tableIds[idx], func() { perfMap.Stop() }, time.Millisecond*500)
	}
	log.Infof("Monitor %s stop", p.Monitor)
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

func showRegisteredEnhancer() {
	if log.ConfigLevel() == log.DLevel {
		mutex.Do(func() {
			l := len(registeredEnhancer)
			if l == 0 {
				return
			}
			enhancers, idx := make([]string, l), 0
			for s := range registeredEnhancer {
				enhancers[idx] = s
				idx++
			}
			log.Debugf("Enhancer %v be registered", enhancers)
		})
	}
}

func dataProcessing(d []byte, tableCtx *TableCtx, ch chan<- *data.AnalyseData) {
	for name, handler := range registeredEnhancer {
		log.Debugf("%s pre handle for %q", name, tableCtx.Name)
		handler.PreHandle(tableCtx)
	}

	log.Infof("Resolve %q...", tableCtx.Name)
	analyseData, err := tableCtx.handler(d)
	log.Debugf("Receive data from %q, %v", tableCtx.Name, analyseData)

	for name, handler := range registeredEnhancer {
		log.Debugf("%s after handle for %q", name, tableCtx.Name)
		analyseData, err = handler.AfterHandle(tableCtx, analyseData, err)
	}

	if err != nil {
		log.Warnf("Event %q resolve error: %v", tableCtx.Name, err)
	} else {
		if len(analyseData.Name) == 0 {
			analyseData.Name = tableCtx.Name
		}
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
		Send: reflect.ValueOf(data.NewErrAnalyseData("", data.Invalid, "")),
	}
	if idx := chCnt + 1; idx < cnt {
		cases[idx] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(stop)}
	}
	return cases, tableNames
}

func initPerMaps(m *bpf.Module, p *PerfResolveMm) []*bpf.PerfMap {
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
