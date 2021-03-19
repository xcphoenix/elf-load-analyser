package content

import (
	"github.com/phoenixxc/elf-load-analyser/pkg/data"
)

type Set struct {
	contents []data.Content
}

func NewContentSet(contents ...data.Content) *Set {
	return &Set{contents: append([]data.Content{}, contents...)}
}

func (c *Set) Class() data.Type {
	return data.UnitType
}

func (c *Set) Data() (res interface{}) {
	res = "[]"
	if len(c.contents) == 0 {
		return
	}
	type ContentData = struct {
		Class int8        `json:"type"`
		Data  interface{} `json:"data"`
	}
	contentDataList := make([]ContentData, len(c.contents))
	for i := range c.contents {
		contentDataList[i] = ContentData{
			Class: int8(c.contents[i].Class()),
			Data:  c.contents[i].Data(),
		}
	}
	return contentDataList
}

func (c *Set) Combine(contents ...data.Content) *Set {
	if len(contents) == 0 {
		return c
	}
	for i := range contents {
		if contents[i] != data.EmptyContent {
			c.contents = append(c.contents, contents[i])
		}
	}
	return c
}
