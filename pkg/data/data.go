package data

import (
	"fmt"
	"strconv"
	"time"
)

type JSONTime time.Time

func (t JSONTime) MarshalJSON() ([]byte, error) {
	stamp := fmt.Sprintf("\"%s\"", time.Time(t).Format("15:04:05.000000"))
	return []byte(stamp), nil
}

// Status Result status
type Status int8

const (
	Success  = Status(iota) // success
	RunError                // exec runtime error, such as kernel function return failed
)

var status2Desc = map[Status]string{
	Success:  "OK",
	RunError: "happened error at runtime",
}

type AnalyseData struct {
	XTime    JSONTime               `json:"time"`
	DataList []*AnalyseData         `json:"dataList"`
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Desc     string                 `json:"desc"`
	Data     *wrapContent           `json:"data"`
	Extra    map[string]interface{} `json:"extra"`
	Status   Status                 `json:"status"`
	XType    Type                   `json:"type"`
}

func (a AnalyseData) String() string {
	return strconv.Quote(fmt.Sprintf("AnalyseData{ID: %s, Name: %s, Status: %s, Desc: %s, "+
		"XTime: %v, Data: %v, DataList: %v, Extra: %v}", a.ID, a.Name, statusDesc(a.Status), a.Desc,
		a.XTime, a.Data, a.DataList, a.Extra))
}

// NewAnalyseData create analyse data.
// name: data name, if name == "" and use advantage_module, will be set `monitor name`@`event name` after rendered;
// builder: cannot be null
func NewAnalyseData(content Content) *AnalyseData {
	return &AnalyseData{
		Name:   "",
		Status: Success,
		XType:  content.Class(),
		Data:   newWrapContent(content),
		Desc:   statusDesc(Success),
		XTime:  JSONTime(time.Now()),
		Extra:  map[string]interface{}{},
	}
}

func NewListAnalyseData(id string, name string, dataList []*AnalyseData) *AnalyseData {
	return &AnalyseData{
		ID:       id,
		Name:     name,
		Status:   Success,
		DataList: dataList,
		Desc:     statusDesc(Success),
		XTime:    JSONTime(time.Now()),
		Extra:    map[string]interface{}{},
	}
}

func NewErrAnalyseData(name string, s Status, desc string) *AnalyseData {
	if s == Success {
		panic("error status cannot be OK")
	}
	if len(desc) == 0 {
		desc = statusDesc(s)
	}
	return &AnalyseData{Status: s, Desc: desc, XTime: JSONTime(time.Now()), Name: name, Extra: map[string]interface{}{}}
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
	delete(a.Extra, k)
}

func (a *AnalyseData) PutExtra(k string, v interface{}) {
	a.Extra[k] = v
}

func (a *AnalyseData) ExtraByKey(k string) (interface{}, bool) {
	v, ok := a.Extra[k]
	return v, ok
}

func statusDesc(s Status) string {
	res, ok := status2Desc[s]
	if !ok {
		return "Unknown Status"
	}
	return res
}
