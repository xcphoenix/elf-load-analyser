package ebpf

import bpf "github.com/iovisor/gobpf/bcc"

type UretprobeEvent struct {
	UprobeEvent
}

func NewUretprobeEvent(name, fnName, fileName string, pid int) *Event {
	e := NewEvent(UretprobeType, name, fnName)
	ke := UretprobeEvent{
		UprobeEvent: UprobeEvent{
			event:    e,
			fileName: fileName,
			pid:      pid,
		},
	}
	e.action = &ke
	return e
}

func (e *UretprobeEvent) Attach(m *bpf.Module, fd int) error {
	return m.AttachUretprobe(e.fileName, e.event.FnName, fd, e.pid)
}
