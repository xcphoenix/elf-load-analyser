package render

import (
    "github.com/phoenixxc/elf-load-analyser/pkg/data"
    "github.com/phoenixxc/elf-load-analyser/pkg/data/content"
    "github.com/phoenixxc/elf-load-analyser/pkg/env"
    "os"
    "runtime"
)

type EnvRender struct{}

func NewEnvRender() *EnvRender {
    return &EnvRender{}
}

func (e *EnvRender) Render() (*data.AnalyseData, error) {
    t := e.Type()
    envContent := content.NewContentSet(
        content.NewTitleMarkdown(content.H2, "内核").WithContents(env.GetKernelVersion()).
            Append(content.NewTitleMarkdown(content.H2, "平台").WithContents(runtime.GOARCH)).
            Append(content.NewTitleMarkdown(content.H2, "环境变量")),
        content.NewList(os.Environ()...),
    )

    return data.NewAnalyseData(t.Name, envContent).WithID(t.ID), nil
}

func (e *EnvRender) Type() Type {
    return EnvType
}

func (e *EnvRender) Release() {}
