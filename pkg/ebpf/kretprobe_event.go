package ebpf

import bpf "github.com/iovisor/gobpf/bcc"

type KretprobeEvent struct {
	KprobeEvent
}

func NewKretprobeEvent(name string, fnName string, maxActive int) *Event {
	e := NewEvent(KretprobeType, name, fnName)
	ke := KretprobeEvent{
		KprobeEvent: KprobeEvent{
			event:     e,
			maxActive: maxActive,
		},
	}
	e.action = &ke
	return e
}

func (e *KretprobeEvent) Attach(m *bpf.Module, fd int) error {
	return m.AttachKretprobe(e.event.FnName, fd, e.maxActive)
}
