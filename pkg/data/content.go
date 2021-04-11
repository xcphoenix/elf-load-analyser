package data

import "encoding/json"

type Type int8

// DataContent Format Type
const (
	UnitType = Type(iota)
	MarkdownType
	ListType
	TableType
)

type Content interface {
	Class() Type
	Data() interface{}
}

type ContentSet struct {
	contents []Content
}

func NewSet(contents ...Content) *ContentSet {
	return (&ContentSet{contents: []Content{}}).Combine(contents...)
}

func (c ContentSet) Class() Type {
	return UnitType
}

func (c ContentSet) Data() (res interface{}) {
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

func (c *ContentSet) Combine(contents ...Content) *ContentSet {
	if len(contents) == 0 {
		return c
	}
	for _, content := range contents {
		if content == EmptyContent {
			continue
		}
		if content.Class() == UnitType {
			if con, ok := content.(ContentSet); ok {
				c.Combine(con.contents...)
			} else if con, ok := content.(*ContentSet); ok {
				c.Combine(con.contents...)
			}
		} else {
			c.contents = append(c.contents, content)
		}
	}
	return c
}

type wrapContent struct{ Content }

var EmptyContent = wrapContent{}

func newWrapContent(content Content) *wrapContent {
	return &wrapContent{Content: NewSet(content)}
}

func (w wrapContent) ContentSet() *ContentSet {
	if s, ok := w.Content.(*ContentSet); ok {
		return s
	}
	return NewSet(w.Content)
}

func (w wrapContent) MarshalJSON() ([]byte, error) {
	return json.Marshal(w.Content.Data())
}
