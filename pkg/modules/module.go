package modules

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"reflect"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
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

type ModuleResolver interface {
	// Resolve 解析、发送处理结果
	Resolve(ctx context.Context, m *bpf.Module, ch chan<- *data.AnalyseData)
}

// MonitorModule 模块抽象接口
type MonitorModule struct {
	// ModuleResolver 解析
	ModuleResolver

	// Monitor 返回模块的名称
	Monitor string
	// Source 返回注入的 bcc 源码
	Source string
	// Events 返回要注册的事件
	Events []*bcc.Event
	// IsEnd 是否标记为最后
	IsEnd bool
	// LazyInit 延迟初始化
	LazyInit func(mm *MonitorModule, param bcc.PreParam) bool
}

// ModuleInit 初始化 Module, 返回创建的 Monitor、是否标记为 end，是否跳过此 Module
func ModuleInit(mm *MonitorModule, param bcc.PreParam) (*bcc.Monitor, bool, bool) {
	// check
	helper.Predicate(func() bool { return mm != nil && len(mm.Monitor) > 0 && len(mm.Source) > 0 }, "Invalid monitor")

	// lazy init
	if mm.LazyInit != nil {
		if skip := mm.LazyInit(mm, param); skip {
			return nil, false, true
		}
	}

	// create
	m := bcc.NewMonitor(mm.Monitor, mm.Source, defaultFlags)
	for _, event := range mm.Events {
		m.AddEvent(event)
	}
	return m, mm.IsEnd, false
}

func RenderHandler(event EventResult) func(data []byte) (*data.AnalyseData, error) {
	return func(data []byte) (*data.AnalyseData, error) {
		return Render(data, event)
	}
}

func Render(d []byte, event EventResult) (*data.AnalyseData, error) {
	err := binary.Read(bytes.NewBuffer(d), bpf.GetHostByteOrder(), event)
	if err != nil {
		return nil, fmt.Errorf("failed to decode received data to %q, %w",
			reflect.TypeOf(event).Name(), err)
	}
	aData := event.Render()
	enhanceStructField(event, aData)

	return aData, nil
}

func enhanceStructField(ptr interface{}, d *data.AnalyseData) {
	reType := reflect.TypeOf(ptr)
	var v = reflect.ValueOf(ptr)
	if reType.Kind() == reflect.Ptr {
		reType = reflect.ValueOf(ptr).Elem().Type()
		v = reflect.ValueOf(ptr).Elem()
	}
	if reType.Kind() != reflect.Struct {
		panic("invalid type" + reType.Kind().String())
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
			if structField.Anonymous && structField.Type.Kind() == reflect.Struct {
				parseField(k, d)
			}
			continue
		}
		d.PutExtra(label, k.Interface())
	}
}
