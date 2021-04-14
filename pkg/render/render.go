package render

import "github.com/xcphoenix/elf-load-analyser/pkg/data"

type Type struct {
	ID   string
	Name string
}

var (
	ElfType     = Type{ID: "_ELF", Name: "文件格式"}
	EnvType     = Type{ID: "_ENV", Name: "系统环境"}
	AnalyseType = Type{ID: "_LOAD", Name: "加载过程"}
)

// Render 渲染器
type Render interface {
	Render() (*data.AnalyseData, error) // Render 渲染数据
	Type() Type                         // Type 渲染类型
	Release()                           // Release 资源释放
}

func doRender(r Render) (d *data.AnalyseData, e error) {
	d, e = r.Render()
	r.Release()
	return
}
