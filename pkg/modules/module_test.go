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
	assert.Equal(t, true, existKey(tmpAnalyseData, "aa"))
	assert.Equal(t, true, existKey(tmpAnalyseData, "bd"))

	tmpAnalyseData = newData()
	enhanceStructField(&bVal, tmpAnalyseData)
	assert.Equal(t, true, existKey(tmpAnalyseData, "aa"))
	assert.Equal(t, true, existKey(tmpAnalyseData, "bd"))

	cVal := struct {
		*StructB
		Cc string `enhance:"cc"`
	}{
		&bVal,
		"",
	}
	tmpAnalyseData = newData()
	enhanceStructField(&cVal, tmpAnalyseData)
	assert.Equal(t, true, existKey(tmpAnalyseData, "aa"))
	assert.Equal(t, true, existKey(tmpAnalyseData, "bd"))
	assert.Equal(t, true, existKey(tmpAnalyseData, "cc"))

	dVal := struct {
		Inf
		Dd interface{} `enhance:"dd"`
	}{
		&cVal,
		struct{}{},
	}
	tmpAnalyseData = newData()
	enhanceStructField(&dVal, tmpAnalyseData)
	assert.Equal(t, true, existKey(tmpAnalyseData, "aa"))
	assert.Equal(t, true, existKey(tmpAnalyseData, "bd"))
	assert.Equal(t, true, existKey(tmpAnalyseData, "cc"))
	assert.Equal(t, true, existKey(tmpAnalyseData, "dd"))
}

func newData() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("..."))
}

func existKey(a *data.AnalyseData, key string) bool {
	_, ok := a.ExtraByKey(key)
	return ok
}
