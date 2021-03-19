package content

import (
	"fmt"
	"github.com/phoenixxc/elf-load-analyser/pkg/data"
)

type Table struct {
	col     int
	desc    string
	head    []string
	content []map[string]string
	handler func(interface{}) (string, bool)
}

func (t *Table) Class() data.Type {
	return data.TableType
}

func (t *Table) Data() interface{} {
	return &struct {
		Data []map[string]string `json:"table"`
		Desc string              `json:"desc"`
	}{
		Data: t.content,
		Desc: t.desc,
	}
}

func (t *Table) Col() int {
	return t.col
}

func NewTable(head ...string) *Table {
	return &Table{head: head, col: len(head), content: []map[string]string{}}
}

func (t *Table) SetHandler(handler func(interface{}) (string, bool)) *Table {
	t.handler = handler
	return t
}

func (t *Table) WithDesc(desc string) *Table {
	t.desc = desc
	return t
}

func (t *Table) AddRow(rows ...interface{}) *Table {
	if len(rows) < t.col {
		for len(rows) < t.col {
			rows = append(rows, "—")
		}
	}
	r := rows[:t.col]
	kv := make(map[string]string, t.col)
	for i := range r {
		kv[t.head[i]] = t.convert(r[i])
	}
	t.content = append(t.content, kv)
	return t
}

func (t *Table) convert(a interface{}) (val string) {
	if t.handler != nil {
		if str, ok := t.handler(a); ok {
			return str
		}
	}
	switch v := a.(type) {
	case string:
		val = v
	case fmt.Stringer:
		val = v.String()
	case fmt.GoStringer:
		val = v.GoString()
	default:
		val = fmt.Sprintf("%v", a)
	}
	return
}
