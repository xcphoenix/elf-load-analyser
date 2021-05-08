package bcc

import (
	"debug/elf"
	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
	"strconv"
	"strings"
)

type Type uint8

const (
	KprobeType    = Type(iota) // kprobe
	KretprobeType              // kretprobe
	UprobeType                 // uprobe
	UretprobeType              // uretprobe
)

func (t Type) String() (name string) {
	switch t {
	case KprobeType:
		name = "kprobe"
	case KretprobeType:
		name = "kretprobe"
	case UprobeType:
		name = "Uprobe"
	case UretprobeType:
		name = "Uretprobe"
	default:
		name = "unknown"
	}
	return
}

type PreParam struct {
	Pid  int
	Path string

	// ELF 文件相关
	Header elf.FileHeader
	IsDyn  bool
	Interp string
}

func BuildCtx(path string) PreParam {
	return PreParam{Path: path}
}

type action interface {
	// Attached symbol
	Attach(m *bpf.Module, fd int) error
	// Loader load symbol
	Load(m *bpf.Module) (int, error)
}

type Event struct {
	action
	Class  Type   // 事件类型
	Name   string // 事件名称
	FnName string // 函数名称
}

func NewEvent(class Type, name string, fnName string) *Event {
	return &Event{Class: class, Name: name, FnName: fnName}
}

type Monitor struct {
	events       []*Event
	event2Action map[*Event]*action
	Name         string
	Source       string
	HeaderDirs   []string // 头文件路径
	CFlags       []string
}

func NewMonitor(name string, source string, cFlags []string) *Monitor {
	return &Monitor{Name: name, Source: source, CFlags: cFlags}
}

// initialize 创建 bpf 模块
func (m *Monitor) initialize() *bpf.Module {
	return bpf.NewModule(m.Source, m.CFlags)
}

// PreProcessing 预处理
func (m *Monitor) PreProcessing(ctx PreParam) {
	if m.event2Action == nil {
		m.event2Action = make(map[*Event]*action)
	}
	// init
	for _, event := range m.events {
		m.event2Action[event] = &event.action
	}
	m.Source = strings.ReplaceAll(m.Source, "_PID_", strconv.Itoa(ctx.Pid))
}

// AddEvent 设置事件
func (m *Monitor) AddEvent(event *Event) *Monitor {
	if m.events == nil {
		m.events = []*Event{}
	}
	m.events = append(m.events, event)
	return m
}

// DoAction 执行 attach operation 操作
func (m *Monitor) DoAction() *bpf.Module {
	if len(m.event2Action) == 0 {
		log.Errorf("Monitor %s missing event", m.Name)
	}

	module := m.initialize()
	for event, action := range m.event2Action {
		log.Debugf("%s@%s#%s start load/attach action...", m.Name, event.FnName, event.Name)

		action := *action
		fd, err := action.Load(module)
		if err != nil {
			log.Errorf("Failed to load event %v, %v", *event, err)
		}
		if err = action.Attach(module, fd); err != nil {
			log.Errorf("Failed to attach event %v, %v", *event, err)
		}
	}
	return module
}
