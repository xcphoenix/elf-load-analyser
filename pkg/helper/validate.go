package helper

import (
	"fmt"
	"reflect"

	"github.com/xcphoenix/elf-load-analyser/pkg/log"
)

type ValidateError struct {
	msg string
}

func (v ValidateError) Error() string {
	return v.msg
}

func EqualWithTip(expected, actual interface{}, errorMsg string) {
	Equal(expected, actual, func(e, a interface{}) {
		log.Error(&ValidateError{msg: errorMsg})
	})
}

func Equal(expected, actual interface{}, handler func(e, a interface{})) {
	Validate(expected, actual, func(expected, actual interface{}) bool {
		return expected == actual
	}, handler)
}

func Predicate(predicate func() bool, errorMsg string) {
	if !predicate() {
		log.Error(&ValidateError{msg: errorMsg})
	}
}

func Validate(expected, actual interface{},
	predicate func(expected, actual interface{}) bool,
	handler func(e, a interface{})) {
	expectedVal, actualVal := getValue(expected), getValue(actual)
	if !predicate(expectedVal, actualVal) {
		handler(expectedVal, actualVal)
	}
}

func isNotFunc(val interface{}) bool {
	if val == nil {
		return false
	}
	return reflect.TypeOf(val).Kind() != reflect.Func
}

func getValue(val interface{}) interface{} {
	if isNotFunc(val) {
		return val
	}
	switch val := val.(type) {
	case func() interface{}:
		return val()
	default:
		panic(fmt.Sprintf("argument %T should be normal value or func() interface{} type", val))
	}
}
