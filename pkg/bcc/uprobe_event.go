package bcc

import (
	bpf "github.com/iovisor/gobpf/bcc"
)

// DefaultPid default pid for all process
const DefaultPid = -1

type UprobeEvent struct {
	*Event
	fileName string
	pid      int
}

func NewUprobeEvent(name, fnName, fileName string, pid int) *Event {
	e := NewEvent(KprobesType, name, fnName)
	ke := UprobeEvent{
		Event:    e,
		fileName: fileName,
		pid:      pid,
	}
	e.action = &ke
	return e
}

func (e UprobeEvent) Attach(m *bpf.Module, fd int) error {
	return m.AttachUprobe(e.fileName, e.FnName, fd, e.pid)
}

func (e *UprobeEvent) Load(m *bpf.Module) (int, error) {
	return m.LoadUprobe(e.Name)
}
