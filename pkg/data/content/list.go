package content

import (
    "github.com/phoenixxc/elf-load-analyser/pkg/data"
)

type List struct {
    list   []string
    length int
}

func (l List) Class() data.Type {
    return data.ListType
}

func (l List) Data() interface{} {
    return &l.list
}

func NewList(list ...string) *List {
    return &List{list: list}
}
