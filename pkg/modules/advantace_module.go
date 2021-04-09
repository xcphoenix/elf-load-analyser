package modules

import (
	"fmt"
	"reflect"
	"strings"
	"sync"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/phoenixxc/elf-load-analyser/pkg/data"
	"github.com/phoenixxc/elf-load-analyser/pkg/log"
)

var (
	mutex              sync.Once
	registeredEnhancer = make(map[string]Enhancer)
)

func RegisteredEnhancer(name string, e Enhancer) {
	registeredEnhancer[name] = e
}

type TableHandler func(data []byte) (*data.AnalyseData, bool, error)

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

// Enhancer enhance on PerfResolveMm.Resolve
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

//nolint:funlen
func (p *PerfResolveMm) Resolve(m *bpf.Module, ch chan<- *data.AnalyseData, ready chan<- struct{}, stop <-chan struct{}) {
	if len(p.tableIds) == 0 {
		log.Warnf("Monitor %q without event", p.Monitor)
		ready <- struct{}{}
		return
	}
	showRegisteredEnhancer()

	perfMaps := initPerMaps(m, p)
	ok := make(chan struct{})

	chCnt := len(p.table2Ctx)
	cnt := chCnt + 2
	remaining := cnt
	cases, tableNames := buildSelectCase(cnt, p.table2Ctx, ready, stop)

	go func() {
		defer func() { close(ok) }()
		lastRemain := 0
		if p.IsEnd() {
			lastRemain++
		}
		for remaining > lastRemain {
			chosen, value, ok := reflect.Select(cases)
			if !value.IsValid() || !ok {
				cases[chosen].Chan = reflect.ValueOf(nil)
				remaining--
				if chosen == chCnt+1 {
					log.Debugf("Monitor %q exit", p.Monitor)
					return
				}
				continue
			}

			tName := tableNames[chosen]
			ctx := p.table2Ctx[tName]

			d := value.Bytes()
			if goOn := dataProcessing(d, ctx, ch); !goOn {
				log.Debugf("Monitor %q quit", p.Monitor)
				return
			}
			if ctx.loop {
				continue
			}
			cases[chosen].Chan = reflect.ValueOf(nil)
			remaining--
		}
		log.Debugf("Monitor %q quit", p.Monitor)
	}()

	for _, perfMap := range perfMaps {
		perfMap.Start()
	}
	log.Infof("Monitor %s start...", p.Monitor)
	<-ok
	for _, perfMap := range perfMaps {
		perfMap.Stop()
	}
	log.Infof("Monitor %s stop...", p.Monitor)
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

func dataProcessing(d []byte, ctx *TableCtx, ch chan<- *data.AnalyseData) bool {
	for name, handler := range registeredEnhancer {
		log.Debugf("%s pre handle for %q", name, ctx.Name)
		handler.PreHandle(ctx)
	}

	log.Infof("Resolve %q...", ctx.Name)
	analyseData, goOn, err := ctx.handler(d)
	log.Debugf("Receive data from %q, %v", ctx.Name, analyseData)

	for name, handler := range registeredEnhancer {
		log.Debugf("%s after handle for %q", name, ctx.Name)
		analyseData, err = handler.AfterHandle(ctx, analyseData, err)
	}

	if err != nil {
		log.Warnf("Event %q resolve error: %v", ctx.Name, err)
	} else {
		if len(analyseData.Name) == 0 {
			analyseData.Name = ctx.Name
		}
		ch <- analyseData
	}
	return goOn
}

func buildSelectCase(cnt int, table2Ctx map[string]*TableCtx, ready chan<- struct{},
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
		Send: reflect.ValueOf(struct{}{}),
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
