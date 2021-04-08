package bcc

import (
	bpf "github.com/iovisor/gobpf/bcc"
)

type KprobeEvent struct {
	inner     *Event
	maxActive int
}

func NewKprobeEvent(name string, fnName string, maxActive int) *Event {
	e := NewEvent(KprobeType, name, fnName)
	ke := KprobeEvent{
		inner:     e,
		maxActive: maxActive,
	}
	e.action = &ke
	return e
}

func (e *KprobeEvent) LazyInit(_ PreParam) {}

func (e *KprobeEvent) Attach(m *bpf.Module, fd int) error {
	return m.AttachKprobe(e.inner.FnName, fd, e.maxActive)
}

func (e *KprobeEvent) Load(m *bpf.Module) (int, error) {
	return m.LoadKprobe(e.inner.Name)
}
