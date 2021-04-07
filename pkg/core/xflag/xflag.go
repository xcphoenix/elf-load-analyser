package xflag

import (
	"flag"
	"fmt"
	"os"
	"time"
)

type Val struct {
	val        interface{}
	name       string
	defaultVal interface{}
	usage      string
	handler    func() error
	optional   bool
}

var holdHandler = make(map[string]func() error)
var mustFlag = make(map[string]struct{})

// flag数据集
type Set struct {
	xFlags []*Val
}

// 注入命令行参数，传入值（除 FunVal 外兼容 flag 包）、名称、默认值、描述、后置处理器
func (f *Set) Inject(val interface{}, name string, defaultVal interface{}, usage string,
	handler func() error) *Set {
	flagVal := &Val{
		val:        val,
		name:       name,
		defaultVal: defaultVal,
		usage:      usage,
		handler:    handler,
		optional:   false,
	}
	f.xFlags = append(f.xFlags, flagVal)
	return f
}

// 注入可选命令行参数，传入值（除 FunVal 外兼容 flag 包）、名称、默认值、描述、后置处理器
func (f *Set) OpInject(val interface{}, name string, defaultVal interface{}, usage string,
	handler func() error) *Set {
	f.Inject(val, name, defaultVal, "(optional) "+usage, handler)
	f.xValList()[len(f.xValList())-1].optional = true
	return f
}

func (f *Set) xValList() []*Val {
	return f.xFlags
}

// 注入命令行参数，调用 Inject
func Inject(val interface{}, name string, defaultVal interface{}, usage string, handler func() error) *Set {
	set := &Set{}
	return set.Inject(val, name, defaultVal, usage, handler)
}

// 注入可选命令行参数，调用 Inject
func OpInject(val interface{}, name string, defaultVal interface{}, usage string, handler func() error) *Set {
	set := &Set{}
	return set.OpInject(val, name, defaultVal, usage, handler)
}

// 添加 Flag
func AddFlag(f *flag.FlagSet, xf *Set) {
	flagValList := xf.xValList()
	for _, xflag := range flagValList {
		switch val := xflag.val.(type) {
		case *bool:
			f.BoolVar(val, xflag.name, xflag.defaultVal.(bool), xflag.usage)
		case *int:
			f.IntVar(val, xflag.name, xflag.defaultVal.(int), xflag.usage)
		case *int64:
			f.Int64Var(val, xflag.name, xflag.defaultVal.(int64), xflag.usage)
		case *uint:
			f.UintVar(val, xflag.name, xflag.defaultVal.(uint), xflag.usage)
		case *uint64:
			f.Uint64Var(val, xflag.name, xflag.defaultVal.(uint64), xflag.usage)
		case *string:
			f.StringVar(val, xflag.name, xflag.defaultVal.(string), xflag.usage)
		case *float64:
			f.Float64Var(val, xflag.name, xflag.defaultVal.(float64), xflag.usage)
		case *time.Duration:
			f.DurationVar(val, xflag.name, xflag.defaultVal.(time.Duration), xflag.usage)
		case flag.Value:
			f.Var(val, xflag.name, xflag.usage)
		default:
			panic("invalid xflag value type")
		}
		if xflag.handler != nil {
			holdHandler[xflag.name] = xflag.handler
		}
		if !xflag.optional {
			mustFlag[xflag.name] = struct{}{}
		}
	}
}

// 添加多个 Flag
func AddFlags(f *flag.FlagSet, xfList ...*Set) {
	if len(xfList) == 0 {
		return
	}
	for _, set := range xfList {
		AddFlag(f, set)
	}
}

// 在默认的 FlagSet 上添加 Flag
func AddCmdFlags(xfList ...*Set) {
	AddFlags(flag.CommandLine, xfList...)
}

// 解析 Flag
func Parse(f *flag.FlagSet) {
	_ = f.Parse(os.Args[1:])
	for name := range mustFlag {
		if f.Lookup(name) == nil {
			fmt.Printf("[%s] must be defined\n", name)
			f.Usage()
			os.Exit(1)
		}
	}
	for name, handle := range holdHandler {
		if err := handle(); err != nil {
			fmt.Printf("[%s] parsed error: %v\n", name, err)
			f.Usage()
			os.Exit(1)
		}
	}
}

// 使用默认的 FlagSet 进行解析
func ParseCmdFlags() {
	Parse(flag.CommandLine)
}
