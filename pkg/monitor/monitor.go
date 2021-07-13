package monitor

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"reflect"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
)

var (
	defaultFlags []string
)

const (
	EnhanceTag = "enhance"
)

// EventResult 事件结果接口，实现中的类型大小在编译时必须是已知的
type EventResult interface {
	// 数据渲染
	Render() *data.AnalyseData
}

// Resolver 模块解析
type Resolver interface {
	// Resolve 解析、发送处理结果
	Resolve(ctx context.Context, m *bpf.Module, ch chan<- *data.AnalyseData)
}

// Builder 模块构造器
type Builder interface {
	// Build 创建模块
	Build() *Monitor
	// Merge 合并模块, moduleList 中的元素不为空
	Merge(moduleList []Builder) []Builder
}

type Type uint

const (
	NormalType Type = iota
	FinallyType
	IgnoredType
)

// Monitor 模块抽象接口
type Monitor struct {
	// Resolver 解析
	Resolver

	// Name 返回模块的名称
	Name string
	// Source 返回注入的 ebpf 源码
	Source string
	// Events 返回要注册的事件
	Events []*ebpf.Event
	// IsEnd 是否标记为最后
	IsEnd bool
	// CanMerge 是否可以与其他 Module 合并
	CanMerge bool
	// LazyInit 延迟初始化
	LazyInit func(mm *Monitor, param ebpf.PreParam) bool
	// Module 获取 `ebpf.Module`
	Module func() *ebpf.Module
}

// InitMonitor 初始化 Module, 返回创建的 Name、是否标记为 end，是否跳过此 Module
func InitMonitor(mm *Monitor, param ebpf.PreParam) Type {
	// check
	helper.Predicate(func() bool {
		return mm != nil && len(mm.Name) > 0 && len(mm.Source) > 0
	}, "Invalid monitor")

	// lazy init
	if mm.LazyInit != nil {
		if skip := mm.LazyInit(mm, param); skip {
			return IgnoredType
		}
	}

	// create
	m := ebpf.NewModule(mm.Name, mm.Source, defaultFlags)
	for _, event := range mm.Events {
		m.AddEvent(event)
	}

	mm.Module = func() *ebpf.Module {
		return m
	}

	if mm.IsEnd {
		return FinallyType
	}
	return NormalType
}

func RenderHandler(event EventResult, eventBuilder func() EventResult) func(data []byte) (*data.AnalyseData, error) {
	if eventBuilder == nil {
		var eventType = reflect.TypeOf(event)
		if eventType.Kind() == reflect.Ptr {
			eventType = eventType.Elem()
		}

		eventBuilder = func() EventResult {
			return reflect.New(eventType).Interface().(EventResult)
		}
	}
	return func(data []byte) (*data.AnalyseData, error) {
		return Render(data, eventBuilder)
	}
}

func Render(d []byte, eventBuilder func() EventResult) (*data.AnalyseData, error) {
	var event = eventBuilder()
	err := binary.Read(bytes.NewBuffer(d), bpf.GetHostByteOrder(), event)
	if err != nil {
		return nil, fmt.Errorf("failed to decode received data to %q, %w",
			reflect.TypeOf(event).Name(), err)
	}

	aData := event.Render()
	if helper.IsNil(aData) {
		log.Warnf("analyse data is not after %T render", event)
		return nil, nil
	}

	enhanceStructField(event, aData)
	return aData, nil
}

func enhanceStructField(ifc interface{}, d *data.AnalyseData) {
	if helper.IsNil(ifc) {
		log.Warnf("value is nil when enhance %v", d)
		return
	}

	var v = reflect.ValueOf(ifc)

	for v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		log.Warnf("enhance value is not struct, %s", v.Type())
		return
	}
	parseField(v, d)
}

func parseField(v reflect.Value, d *data.AnalyseData) {
	for i := 0; i < v.NumField(); i++ {
		structField := v.Type().Field(i)

		k := v.Field(i)
		if !k.CanInterface() {
			continue
		}

		tag := structField.Tag
		label := tag.Get(EnhanceTag)
		if label == "" {
			if structField.Anonymous {
				for k.Kind() == reflect.Interface || k.Kind() == reflect.Ptr {
					k = k.Elem()
				}
				if k.Kind() == reflect.Struct {
					parseField(k, d)
				}
			}
			continue
		}
		d.PutExtra(label, k.Interface())
	}
}
