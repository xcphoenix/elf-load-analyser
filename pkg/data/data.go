package data

import (
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"strconv"
	"time"
)

type JSONTime time.Time

func (t JSONTime) MarshalJSON() ([]byte, error) {
	stamp := fmt.Sprintf("\"%s\"", time.Time(t).Format("15:04:05.000000"))
	return []byte(stamp), nil
}

type AnalyseData struct {
	XTime    JSONTime       `json:"time"`
	DataList []*AnalyseData `json:"dataList"`
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Desc     string         `json:"desc"`
	Data     *wrapContent   `json:"data"`
	Status   Status         `json:"status"`
	XType    Type           `json:"type"`

	extra    map[string]interface{}
	initChan chan struct{}
	lazyFunc func(aData *AnalyseData) Content // 延迟处理函数, 要求返回 Content，避免忘记返回实际的数据内容
}

func newAnalyseData(status Status, desc string, content Content, dataList []*AnalyseData,
	lazyFunc func(aData *AnalyseData) Content) *AnalyseData {
	a := &AnalyseData{
		XTime:    JSONTime(time.Now()),
		DataList: dataList,
		Desc:     status.String(),
		Status:   status,
		lazyFunc: lazyFunc,
		extra:    map[string]interface{}{},
		initChan: make(chan struct{}),
	}
	if len(desc) > 0 {
		a.Desc = desc
	}
	if helper.IsNotNil(content) {
		a.Data = newWrapContent(content)
		a.XType = content.Class()
	}
	if lazyFunc == nil {
		close(a.initChan)
	} else {
		go a.doLazyFunc()
	}
	return a
}

func (a AnalyseData) String() string {
	return strconv.Quote(fmt.Sprintf("AnalyseData{ID: %s, Name: %s, Status: %s, String: %s, "+
		"XTime: %v, Data: %v, DataList: %v, Extra: %v}", a.ID, a.Name, a.Status, a.Desc,
		a.XTime, a.Data, a.DataList, a.extra))
}

// NewAnalyseData create analyse data.
// name: data name, if name == "" and use advantage_module, will be set `monitor name`@`event name` after rendered;
// builder: cannot be null
func NewAnalyseData(content Content) *AnalyseData {
	return newAnalyseData(OkStatus, "", content, nil, nil)
}

func NewLazyAnalyseData(lazyFunc func(aData *AnalyseData) Content) *AnalyseData {
	return newAnalyseData(OkStatus, "", nil, nil, lazyFunc)
}

func NewListAnalyseData(id string, name string, dataList []*AnalyseData) *AnalyseData {
	return newAnalyseData(OkStatus, "", nil, dataList, nil).WithID(id).WithName(name)
}

func NewOtherAnalyseData(s Status, desc string, content Content) *AnalyseData {
	return newAnalyseData(s, desc, content, nil, nil)
}

func (a *AnalyseData) WaitReady() {
	<-a.initChan
}

func (a *AnalyseData) Change(changer func(set ContentSet) Content) {
	oldSet := a.Data.ContentSet()
	a.Data = newWrapContent(changer(*oldSet))
}

func (a *AnalyseData) WithName(name string) *AnalyseData {
	a.Name = name
	return a
}

func (a *AnalyseData) WithID(id string) *AnalyseData {
	a.ID = id
	return a
}

func (a *AnalyseData) RmExtra(k string) {
	delete(a.extra, k)
}

func (a *AnalyseData) PutExtra(k string, v interface{}) *AnalyseData {
	a.extra[k] = v
	return a
}

func (a *AnalyseData) ExtraByKey(k string) (interface{}, bool) {
	v, ok := a.extra[k]
	return v, ok
}

func (a *AnalyseData) doLazyFunc() {
	if a.lazyFunc == nil {
		return
	}
	c := a.lazyFunc(a)
	a.XType = c.Class()
	a.Data = newWrapContent(c)

	a.lazyFunc = nil
	close(a.initChan)
}
