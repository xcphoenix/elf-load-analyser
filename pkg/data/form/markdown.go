package form

import (
	"bytes"
	"strings"

	"github.com/phoenixxc/elf-load-analyser/pkg/data"
)

type ItemLevel uint8

const (
	H1 = ItemLevel(iota + 1)
	H2
	H3
	H4
)

type Markdown struct {
	level         ItemLevel
	title         string
	content       string
	appendContent []string
}

func (m Markdown) Class() data.Type {
	return data.MarkdownType
}

func (m Markdown) String() string {
	var buf bytes.Buffer
	buf.Grow(int(m.level) + len(m.title) + len(m.content) + 5)
	if len(m.title) > 0 && m.level != 0 {
		for k := 0; k < int(m.level); k++ {
			buf.WriteRune('#')
		}
		buf.WriteRune(' ')
		buf.WriteString(m.title)
		buf.WriteString("\n\n")
	}
	if len(m.content) > 0 {
		buf.WriteString(m.content)
		buf.WriteString("\n\n")
	}
	if len(m.appendContent) > 0 {
		buf.WriteString(strings.Join(m.appendContent, ""))
	}
	return buf.String()
}

func (m Markdown) Data() interface{} {
	return m.String()
}

func NewMarkdown(content ...string) *Markdown {
	m := &Markdown{appendContent: []string{}}
	return m.WithContents(content...)
}

func NewTitleMarkdown(level ItemLevel, title string) *Markdown {
	return &Markdown{level: level, title: title, appendContent: []string{}}
}

func (m *Markdown) WithContents(content ...string) *Markdown {
	m.content = strings.Join(content, "\n\n")
	return m
}

func (m *Markdown) Append(am *Markdown) *Markdown {
	if len(am.title) == 0 && len(am.content) == 0 && len(am.appendContent) == 0 {
		return m
	}
	m.appendContent = append(m.appendContent, am.String())
	return m
}
