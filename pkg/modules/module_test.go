package modules

import (
	"github.com/stretchr/testify/assert"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"testing"
)

type StructA struct {
	Aa string `enhance:"aa"`
}

type StructB struct {
	StructA
	Ba string
	Bc int
	Bd float64 `enhance:"bd"`
}

type Inf interface{}

func Test_enhanceStructField(t *testing.T) {
	bVal := StructB{
		StructA: StructA{},
		Ba:      "",
		Bc:      0,
		Bd:      0,
	}

	tmpAnalyseData := newData()
	enhanceStructField(bVal, tmpAnalyseData)
	extraMap := tmpAnalyseData.Extra
	assert.Equal(t, true, existKey(extraMap, "aa"))
	assert.Equal(t, true, existKey(extraMap, "bd"))

	tmpAnalyseData = newData()
	enhanceStructField(&bVal, tmpAnalyseData)
	extraMap = tmpAnalyseData.Extra
	assert.Equal(t, true, existKey(extraMap, "aa"))
	assert.Equal(t, true, existKey(extraMap, "bd"))

	cVal := struct {
		*StructB
		Cc string `enhance:"cc"`
	}{
		&bVal,
		"",
	}
	tmpAnalyseData = newData()
	enhanceStructField(&cVal, tmpAnalyseData)
	extraMap = tmpAnalyseData.Extra
	assert.Equal(t, true, existKey(extraMap, "aa"))
	assert.Equal(t, true, existKey(extraMap, "bd"))
	assert.Equal(t, true, existKey(extraMap, "cc"))

	dVal := struct {
		Inf
		Dd interface{} `enhance:"dd"`
	}{
		&cVal,
		struct{}{},
	}
	tmpAnalyseData = newData()
	enhanceStructField(&dVal, tmpAnalyseData)
	extraMap = tmpAnalyseData.Extra
	assert.Equal(t, true, existKey(extraMap, "aa"))
	assert.Equal(t, true, existKey(extraMap, "bd"))
	assert.Equal(t, true, existKey(extraMap, "cc"))
	assert.Equal(t, true, existKey(extraMap, "dd"))
}

func newData() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("..."))
}

func existKey(m map[string]interface{}, key string) bool {
	_, ok := m[key]
	return ok
}

func value(m map[string]interface{}, key string) interface{} {
	val, ok := m[key]
	if ok {
		return val
	}
	return nil
}
