package ebpf

import (
	bpf "github.com/iovisor/gobpf/bcc"
)

type KprobeEvent struct {
	event     *Event
	maxActive int
}

func NewKprobeEvent(name string, fnName string, maxActive int) *Event {
	e := NewEvent(KprobeType, name, fnName)
	ke := KprobeEvent{
		event:     e,
		maxActive: maxActive,
	}
	e.action = &ke
	return e
}

func (e *KprobeEvent) Attach(m *bpf.Module, fd int) error {
	return m.AttachKprobe(e.event.FnName, fd, e.maxActive)
}

func (e *KprobeEvent) Load(m *bpf.Module) (int, error) {
	return m.LoadKprobe(e.event.Name)
}
