package ebpf

import (
	"debug/elf"
	bpf "github.com/iovisor/gobpf/bcc"
	log "github.com/sirupsen/logrus"
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

type Module struct {
	events       []*Event
	event2Action map[*Event]*action
	Name         string
	Source       string
	CFlags       []string
}

func NewModule(name string, source string, cFlags []string) *Module {
	return &Module{Name: name, Source: source, CFlags: cFlags}
}

// initialize 创建 bpf 模块
func (m *Module) initialize() *bpf.Module {
	return bpf.NewModule(m.Source, m.CFlags)
}

// PreProcessing 预处理
func (m *Module) PreProcessing(ctx PreParam) {
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
func (m *Module) AddEvent(event *Event) *Module {
	if m.events == nil {
		m.events = []*Event{}
	}
	m.events = append(m.events, event)
	return m
}

// DoAction 执行 attach operation 操作
func (m *Module) DoAction() *bpf.Module {
	if len(m.event2Action) == 0 {
		log.Fatalf("Name %s missing event", m.Name)
	}

	module := m.initialize()
	for event, action := range m.event2Action {
		log.Debugf("%s@%s#%s start load/attach action...", m.Name, event.FnName, event.Name)

		action := *action
		fd, err := action.Load(module)
		if err != nil {
			log.Fatalf("Failed to load event %v, %v", *event, err)
		}
		if err = action.Attach(module, fd); err != nil {
			log.Fatalf("Failed to attach event %v, %v", *event, err)
		}
	}
	return module
}
