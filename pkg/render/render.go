package render

import "github.com/phoenixxc/elf-load-analyser/pkg/data"

type Ctx struct {
    Filepath string
}

func NewCtx(filepath string) *Ctx {
    return &Ctx{Filepath: filepath}
}

type Type struct {
    ID   string
    Name string
}

var (
    ElfType     = Type{ID: "_ELF", Name: "文件格式"}
    EnvType     = Type{ID: "_ENV", Name: "系统环境"}
    AnalyseType = Type{ID: "_LOAD", Name: "加载过程"}
)

type Render interface {
    Render() (*data.AnalyseData, error)
    Type() Type
    Release()
}

func doRender(r Render) (d *data.AnalyseData, e error) {
    d, e = r.Render()
    r.Release()
    return
}
