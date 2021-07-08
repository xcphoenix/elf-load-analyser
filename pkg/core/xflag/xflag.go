package xflag

import (
	"errors"
	"flag"
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"os"
	"reflect"
	"time"

	"github.com/xcphoenix/elf-load-analyser/pkg/core/state"
)

type FlagError struct {
	Msg string
}

func (e FlagError) Error() string {
	return e.Msg
}

type ArgValidator func() error

type FlagValue struct {
	Target       interface{}
	Name         string
	DefaultValue interface{}
	Usage        string
	Validator    ArgValidator
}

func NewFlagValue(target interface{}, name string, usage string) *FlagValue {
	return &FlagValue{
		Target: target,
		Name:   name,
		Usage:  usage,
	}
}

func (f *FlagValue) WithDefault(value interface{}) *FlagValue {
	f.DefaultValue = value
	return f
}

func (f *FlagValue) WithValidator(validator ArgValidator) *FlagValue {
	f.Validator = validator
	return f
}

type FlagSet struct {
	initialized  bool
	innerFlagSet *flag.FlagSet
	xFlags       []*FlagValue
	argValidator map[string]ArgValidator
	optionalArgs map[string]struct{}
}

func NewFlagSet() *FlagSet {
	return &FlagSet{
		initialized:  false,
		xFlags:       make([]*FlagValue, 0),
		optionalArgs: make(map[string]struct{}),
		argValidator: make(map[string]ArgValidator),
	}
}

func (flagSet *FlagSet) merge(other *FlagSet) {
	flagSet.xFlags = append(flagSet.xFlags, other.xFlags...)
	for name, handlers := range other.argValidator {
		flagSet.argValidator[name] = handlers
	}
	for name := range other.optionalArgs {
		flagSet.optionalArgs[name] = struct{}{}
	}
}

// 注入命令行参数，传入值（除 FunVal 外兼容 flag 包）、名称、默认值、描述、后置处理器
func (flagSet *FlagSet) Inject(values ...*FlagValue) *FlagSet {
	for _, value := range values {
		if helper.IsNil(value) || len(value.Name) == 0 || helper.IsNil(value.Target) {
			panic(fmt.Sprintf("illegal flag value: %v", value))
		}

		if helper.IsNil(value.DefaultValue) {
			value.DefaultValue = createByType(value.Target)
		}

		flagSet.xFlags = append(flagSet.xFlags, value)
		if helper.IsNotNil(value.Validator) {
			flagSet.argValidator[value.Name] = value.Validator
		}
	}
	return flagSet
}

// 注入可选命令行参数，传入值（除 FunVal 外兼容 flag 包）、名称、默认值、描述、后置处理器
func (flagSet *FlagSet) OpInject(values ...*FlagValue) *FlagSet {
	for _, value := range values {
		value.Usage = "(optional) " + value.Usage
		flagSet.Inject(value)
		flagSet.optionalArgs[value.Name] = struct{}{}
	}
	return flagSet
}

func (flagSet *FlagSet) xValList() []*FlagValue {
	return flagSet.xFlags
}

// 注入命令行参数，调用 Inject
func Inject(values ...*FlagValue) *FlagSet {
	set := NewFlagSet()
	return set.Inject(values...)
}

// 注入可选命令行参数，调用 Inject
func OpInject(values ...*FlagValue) *FlagSet {
	set := NewFlagSet()
	return set.OpInject(values...)
}

func injectFlags(f *flag.FlagSet, xf *FlagSet) {
	flagValList := xf.xValList()
	for _, xflag := range flagValList {
		switch val := xflag.Target.(type) {
		case *bool:
			f.BoolVar(val, xflag.Name, xflag.DefaultValue.(bool), xflag.Usage)
		case *int:
			f.IntVar(val, xflag.Name, xflag.DefaultValue.(int), xflag.Usage)
		case *int64:
			f.Int64Var(val, xflag.Name, xflag.DefaultValue.(int64), xflag.Usage)
		case *uint:
			f.UintVar(val, xflag.Name, xflag.DefaultValue.(uint), xflag.Usage)
		case *uint64:
			f.Uint64Var(val, xflag.Name, xflag.DefaultValue.(uint64), xflag.Usage)
		case *string:
			f.StringVar(val, xflag.Name, xflag.DefaultValue.(string), xflag.Usage)
		case *float64:
			f.Float64Var(val, xflag.Name, xflag.DefaultValue.(float64), xflag.Usage)
		case *time.Duration:
			f.DurationVar(val, xflag.Name, xflag.DefaultValue.(time.Duration), xflag.Usage)
		case flag.Value:
			f.Var(val, xflag.Name, xflag.Usage)
		default:
			panic(fmt.Sprintf("unsupported xflag value type: %T", xflag.Target))
		}
	}
}

// 添加多个 Flags
func Bind(f *flag.FlagSet, xfList ...*FlagSet) *FlagSet {
	var initedFlagSet = NewFlagSet()
	initedFlagSet.initialized = true
	initedFlagSet.innerFlagSet = f

	if helper.IsNil(f) || len(xfList) == 0 {
		return initedFlagSet
	}

	for _, set := range xfList {
		if helper.IsNil(set) {
			continue
		}
		injectFlags(f, set)
		initedFlagSet.merge(set)
	}

	return initedFlagSet
}

// 在默认的 FlagSet 上添加 Flags
func DefaultBind(xfList ...*FlagSet) *FlagSet {
	return Bind(flag.CommandLine, xfList...)
}

// 解析 Flags
func (flagSet *FlagSet) Parse() {
	if !flagSet.initialized {
		panic("flagSet not binding cmd args")
	}

	var innerFlag = flagSet.innerFlagSet

	state.RegisterHandler(state.AbnormalExit, func(err error) error {
		var fe *FlagError
		if errors.As(err, &fe) {
			fmt.Println(fe.Msg)
			innerFlag.Usage()
		}
		return nil
	})

	_ = innerFlag.Parse(os.Args[1:])
	var flagMap = make(map[string]bool)
	innerFlag.VisitAll(func(f *flag.Flag) {
		flagMap[f.Name] = true
	})

	for _, xflag := range flagSet.xFlags {
		var name = xflag.Name
		if _, ok := flagSet.optionalArgs[name]; ok {
			continue
		}
		if !flagMap[name] {
			state.WithError(FlagError{fmt.Sprintf("arg [%s] must be defined\n", name)})
			return
		}
	}

	for _, xflag := range flagSet.xFlags {
		var name = xflag.Name

		if validator, ok := flagSet.argValidator[name]; ok {
			var err = validator()
			if helper.IsNil(err) {
				continue
			}
			state.WithError(FlagError{fmt.Sprintf("parsed arg [%s] error: %v\n", name, err)})
			return
		}
	}
}

func createByType(target interface{}) interface{} {
	if target == nil {
		return nil
	}

	if _, ok := target.(flag.Value); ok {
		return nil
	}

	t := reflect.TypeOf(target)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return reflect.New(t).Elem().Interface()
}
