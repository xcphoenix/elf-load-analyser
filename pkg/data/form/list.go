package form

import (
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
)

type Fmt [][]interface{}

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

func NewFmtList(lists Fmt) *List {
	items := make([]string, len(lists))
	for i, list := range lists {
		if len(list) == 0 {
			continue
		}
		var format string
		var ok bool
		if format, ok = list[0].(string); !ok {
			continue
		}
		items[i] = fmt.Sprintf(format, list[1:]...)
	}
	return &List{items: items}
}
