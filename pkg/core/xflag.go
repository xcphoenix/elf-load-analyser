package core

import (
	"flag"
	"fmt"
	"os"
	"time"
)

type xFlagVal struct {
	val        interface{}
	name       string
	defaultVal interface{}
	usage      string
	handler    func() error
}

var holdHandler = make(map[string]func() error)

type XFlagSet struct {
	xFlags []*xFlagVal
}

func (f *XFlagSet) InjectFlag(val interface{}, name string, defaultVal interface{}, usage string, handler func() error) *XFlagSet {
	flagVal := &xFlagVal{
		val:        val,
		name:       name,
		defaultVal: defaultVal,
		usage:      usage,
		handler:    handler,
	}
	f.xFlags = append(f.xFlags, flagVal)
	return f
}

func (f *XFlagSet) xValList() []*xFlagVal {
	return f.xFlags
}

func InjectFlag(val interface{}, name string, defaultVal interface{}, usage string,
	handler func() error) *XFlagSet {
	set := &XFlagSet{}
	return set.InjectFlag(val, name, defaultVal, usage, handler)
}

func AddFlag(f *flag.FlagSet, xf *XFlagSet) {
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
	}
}

func AddFlags(f *flag.FlagSet, xfList ...*XFlagSet) {
	if len(xfList) == 0 {
		return
	}
	for _, set := range xfList {
		AddFlag(f, set)
	}
}

func AddCmdFlags(xfList ...*XFlagSet) {
	AddFlags(flag.CommandLine, xfList...)
}

func ParseFlags(f *flag.FlagSet) {
	_ = f.Parse(os.Args[1:])
	for name, handle := range holdHandler {
		if err := handle(); err != nil {
			fmt.Printf("[%s] parsed error: %v\n", name, err)
			f.Usage()
			os.Exit(1)
		}
	}
}

func ParseCmdFlags() {
	ParseFlags(flag.CommandLine)
}
