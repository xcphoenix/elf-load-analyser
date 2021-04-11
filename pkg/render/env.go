package render

import (
	"os"
	"runtime"

	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/env"
)

type EnvRender struct{}

func NewEnvRender() *EnvRender {
	return &EnvRender{}
}

func (e *EnvRender) Render() (*data.AnalyseData, error) {
	t := e.Type()
	envContent := data.NewSet(
		form.NewTitleMarkdown(form.H2, "内核").WithContents(env.GetKernelVersion()).
			Append(form.NewTitleMarkdown(form.H2, "平台").WithContents(runtime.GOARCH)).
			Append(form.NewTitleMarkdown(form.H2, "环境变量")),
		form.NewList(os.Environ()...).SetKv(),
	)

	return data.NewAnalyseData(envContent).WithName(t.Name).WithID(t.ID), nil
}

func (e *EnvRender) Type() Type {
	return EnvType
}

func (e *EnvRender) Release() {}
