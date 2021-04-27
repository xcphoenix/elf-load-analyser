package data

import "strconv"

// Status 数据状态
type Status int32

func newStatus(idx, flags int16) Status {
	return Status((int32(idx) << 16) | int32(flags))
}

func (s Status) MarshalJSON() ([]byte, error) {
	idx := strconv.Itoa(int(s.idx()))
	return []byte(idx), nil
}

func (s Status) String() string {
	res, ok := status2Desc[s.idx()]
	if !ok {
		return "Unknown Status"
	}
	return res
}

func (s Status) idx() int16 {
	return int16(s >> 16)
}

func (s Status) flags() int16 {
	return int16(s)
}

const (
	noneFlag    = 0x0
	validFlag   = 0x1             // 状态是否有效
	successFlag = 0x2 | validFlag // 状态是否正常
	finishFlag  = 0x4 | validFlag // 是否标识为结束
)

var (
	OkStatus      = newStatus(0, successFlag) // 成功
	RunErrStatus  = newStatus(1, validFlag)   // 模块运行错误，表示特定的函数执行失败
	BugStatus     = newStatus(2, validFlag)   // 由于未知BUG出现了某种预料之外的情况
	InvalidStatus = newStatus(3, noneFlag)    // 无效状态，将被忽略

	// TODO support shouldRetStatus
	shouldRetStatus = newStatus(OkStatus.idx(), OkStatus.flags()|finishFlag) // OkStatus 的特殊情况，将忽略之后的事件
)

var status2Desc = map[int16]string{
	OkStatus.idx():     "OK",
	RunErrStatus.idx(): "happened error at runtime",
	BugStatus.idx():    "bug",
}

func IsValid(s Status) bool {
	return withFlag(s, validFlag)
}

func ShouldReturn(s Status) bool {
	return withFlag(s, finishFlag)
}

func withFlag(s Status, flag int16) bool {
	return s.flags()&flag != 0
}
