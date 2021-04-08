package bcc

import (
	bpf "github.com/iovisor/gobpf/bcc"
)

// DefaultUprobePid default pid for all process
const DefaultUprobePid = -1

const PlaceholderPid = -2

type UprobeEvent struct {
	inner    *Event
	fileName string
	pid      int
}

func NewUprobeEvent(name, fnName, fileName string, pid int) *Event {
	e := NewEvent(UprobeType, name, fnName)
	ue := UprobeEvent{
		inner:    e,
		fileName: fileName,
		pid:      pid,
	}
	e.action = &ue
	return e
}

func (e *UprobeEvent) Attach(m *bpf.Module, fd int) error {
	return m.AttachUprobe(e.fileName, e.inner.FnName, fd, e.pid)
}

func (e *UprobeEvent) Load(m *bpf.Module) (int, error) {
	return m.LoadUprobe(e.inner.Name)
}

func (e *UprobeEvent) LazyInit(ctx PreParam) {
	if len(e.fileName) == 0 {
		e.fileName = ctx.Path
	}
	if e.pid == PlaceholderPid {
		e.pid = ctx.Pid
	}
}
