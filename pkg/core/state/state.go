package state

import (
	"context"
	"fmt"
	"log"
	"os"
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

func isIllegal(from State, to State, inner bool) bool {
	if inner && from == AbnormalExit && to == Exit {
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

// EventHandler state changed handler
type EventHandler func(error) error

type stateContext struct {
	cancelFunc    context.CancelFunc
	state2events  map[State][]EventHandler
	currentState  State
	abnormalError error
}

func newContext() *stateContext {
	return &stateContext{
		state2events:  make(map[State][]EventHandler, Exit-initState+1),
		currentState:  initState,
		abnormalError: nil,
	}
}

// RegisterHandler register handler, handler will be touched when state be changed from other to s
func (c *stateContext) RegisterHandler(s State, e EventHandler) {
	if isInvalid(s) {
		panic(fmt.Sprintf("illegal state: %v", s))
	}
	c.state2events[s] = append(c.state2events[s], e)
}

func (c *stateContext) pushStateInner(s State, inner bool) {
	if isIllegal(c.currentState, s, inner) {
		panic(fmt.Sprintf("illegal update from %v to %v", c.currentState, s))
	}
	c.currentState = s
	for s, handler := range c.state2events[s] {
		if e := handler(c.abnormalError); e != nil {
			log.Printf("handler on state[%v] failed: %v", s, e)
		}
	}
	if s == Exit {
		if c.cancelFunc != nil {
			// cancel context
			c.cancelFunc()
		}

		fmt.Println()
		if c.abnormalError != nil {
			log.Fatalf("Program exited by error: %v", c.abnormalError)
		} else {
			log.Println("Program stopped")
			os.Exit(0)
		}
	}
	if s == AbnormalExit {
		c.pushStateInner(Exit, true)
	}
}

// Create ctx
func (c *stateContext) CreateContent() context.Context {
	ctx, cancelFunc := context.WithCancel(context.Background())
	c.cancelFunc = cancelFunc
	return ctx
}

// PushState push state to s
func (c *stateContext) PushState(s State) {
	if s == AbnormalExit {
		panic("Please use `WithError` to push state to AbnormalExit with error")
	}
	c.pushStateInner(s, false)
}

// WithError Change state to AbnormalExit and set error
func (c *stateContext) WithError(e error) {
	if c.currentState == AbnormalExit {
		panic("Cannot repeat call `WithError`")
	}
	c.abnormalError = e
	c.pushStateInner(AbnormalExit, false)
}

var defaultContext = newContext()

// RegisterHandler register handler on default stateContext
func RegisterHandler(s State, e EventHandler) {
	defaultContext.RegisterHandler(s, e)
}

// PushState push current state to s on default stateContext
func PushState(s State) {
	defaultContext.PushState(s)
}

// WithError Change state to AbnormalExit and set error
func WithError(e error) {
	defaultContext.WithError(e)
}

func CreateRootContent() context.Context {
	return defaultContext.CreateContent()
}
