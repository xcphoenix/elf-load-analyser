package env

import (
	_ "embed" // embed for banner.txt
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
)

var BannerLen string

const (
	kvDelimiter = ": \t"
)

//go:embed banner.txt
var banner string

//go:embed status.json
var status string

// key value
type Entry struct {
	Key string `json:"key"`
	Val string `json:"val"`
}

func (e Entry) parse() string {
	return e.Key + kvDelimiter + e.Val
}

// 输出 banner 以及版本信息
func EchoBanner() {
	kvList := parseStatus()
	if len(kvList) == 0 {
		fmt.Println(banner)
	}

	bannerLines := strings.Split(banner, "\n")
	kvLen, banLen := len(kvList), len(bannerLines)
	startIdx := helper.IfElse(kvLen >= banLen, 0, (banLen-kvLen)/2).(int)

	bannerMaxLen, _ := strconv.Atoi(BannerLen)
	if bannerMaxLen == 0 {
		bannerMaxLen = 48
	}
	for i, s := range bannerLines {
		fmt.Printf("%-*.*s", bannerMaxLen, bannerMaxLen, s)
		if bIdx := i - startIdx; bIdx >= 0 && bIdx < kvLen {
			fmt.Print(kvList[bIdx])
		}
		fmt.Println()
	}
	for i := banLen; i < kvLen; i++ {
		fmt.Printf("%-.*s\n", banLen+len(kvList[i]), kvList[i])
	}
}

func parseStatus() (kv []string) {
	var s []Entry
	err := json.Unmarshal([]byte(status), &s)
	if err != nil {
		return []string{}
	}
	entries := s
	kv = make([]string, len(entries))
	for idx, entry := range entries {
		kv[idx] = entry.parse()
	}
	return
}
