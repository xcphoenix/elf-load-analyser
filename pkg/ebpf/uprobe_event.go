package ebpf

import (
	bpf "github.com/iovisor/gobpf/bcc"
)

type UprobeEvent struct {
	event    *Event
	fileName string
	pid      int
}

// NewUprobeEvent 创建 UprobeEvent, name: ebpf 对应的函数名, fnName: 用户程序目标函数, fileName: 用户程序路径, pid: 进程 pid
func NewUprobeEvent(name, fnName, fileName string, pid int) *Event {
	e := NewEvent(UprobeType, name, fnName)
	ue := UprobeEvent{
		event:    e,
		fileName: fileName,
		pid:      pid,
	}
	e.action = &ue
	return e
}

func (e *UprobeEvent) Attach(m *bpf.Module, fd int) error {
	return m.AttachUprobe(e.fileName, e.event.FnName, fd, e.pid)
}

func (e *UprobeEvent) Load(m *bpf.Module) (int, error) {
	return m.LoadUprobe(e.event.Name)
}
