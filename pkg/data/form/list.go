package form

import (
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
)

type List struct {
	items  []string
	length int
	kv     bool
}

func (l List) Class() data.Type {
	return data.ListType
}

func (l List) Data() interface{} {
	return struct {
		Items []string `json:"items"`
		Kv    bool     `json:"kv"`
	}{
		l.items, l.kv,
	}
}

func (l *List) SetKv() *List {
	l.kv = true
	return l
}

func NewList(list ...string) *List {
	return &List{items: list}
}
