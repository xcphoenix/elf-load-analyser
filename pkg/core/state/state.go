package state

import (
	"fmt"
	"log"
	"os"
	"sync"
)

type State int

const (
	initState      = State(iota) // 初始状态
	ProcessCreated               // 进程创建完毕
	MonitorLoaded                // 监视器加载完毕
	ProgramLoaded                // 程序加载完毕
	AbnormalExit                 // 异常退出，包括加载异常、子进程终止异常
	Exit                         // 正常退出
)

func isInvalid(s State) bool {
	return s < initState || s > Exit
}

func isIllegal(from State, to State, isInternal bool) bool {
	if isInternal && from == AbnormalExit && to == Exit {
		return false
	}
	if isInvalid(from) || isInvalid(to) {
		return true
	}
	if from == AbnormalExit || from == Exit {
		return true
	}
	if to == AbnormalExit || to == Exit {
		return false
	}
	return from+1 != to
}

// EventHandler state changed enhance
type EventHandler func(error) error

type stateCtx struct {
	state2events  map[State][]EventHandler
	currentState  State
	abnormalError error
	mutex         sync.Mutex
}

func newStateCtx() *stateCtx {
	return &stateCtx{
		state2events:  make(map[State][]EventHandler, Exit-initState+1),
		currentState:  initState,
		abnormalError: nil,
	}
}

// RegisterHandler register enhance, enhance will be touched when state be changed from other to s
func (ctx *stateCtx) RegisterHandler(s State, e EventHandler) {
	if isInvalid(s) {
		panic(fmt.Sprintf("illegal state: %v", s))
	}

	ctx.mutex.Lock()
	defer ctx.mutex.Unlock()
	ctx.state2events[s] = append(ctx.state2events[s], e)
}

func (ctx *stateCtx) updateStateInternal(s State, isInternal bool) {
	if isIllegal(ctx.currentState, s, isInternal) {
		panic(fmt.Sprintf("illegal update from %v to %v", ctx.currentState, s))
	}
	ctx.currentState = s
	for s, handler := range ctx.state2events[s] {
		if e := handler(ctx.abnormalError); e != nil {
			log.Printf("enhance on state[%v] failed: %v", s, e)
		}
	}
	if s == Exit {
		fmt.Println()
		if ctx.abnormalError != nil {
			log.Fatalf("Program exited by error: %v", ctx.abnormalError)
		} else {
			log.Println("Program stopped")
			os.Exit(0)
		}
	}
	if s == AbnormalExit {
		ctx.updateStateInternal(Exit, true)
	}
}

// UpdateState push state to s
func (ctx *stateCtx) UpdateState(s State) {
	if s == AbnormalExit {
		panic("Please use `WithError` to push state to AbnormalExit with error")
	}

	ctx.mutex.Lock()
	defer ctx.mutex.Unlock()

	ctx.updateStateInternal(s, false)
}

// WithError Change state to AbnormalExit and set error
func (ctx *stateCtx) WithError(e error) {
	if ctx.currentState == AbnormalExit {
		panic("Cannot repeat call `WithError`")
	}

	ctx.mutex.Lock()
	defer ctx.mutex.Unlock()

	ctx.abnormalError = e
	ctx.updateStateInternal(AbnormalExit, false)
}

var defaultContext = newStateCtx()

// RegisterHandler register enhance on default stateCtx
func RegisterHandler(s State, e EventHandler) {
	defaultContext.RegisterHandler(s, e)
}

// UpdateState push current state to s on default stateCtx
func UpdateState(s State) {
	defaultContext.UpdateState(s)
}

// WithError Change state to AbnormalExit and set error
func WithError(e error) {
	defaultContext.WithError(e)
}
