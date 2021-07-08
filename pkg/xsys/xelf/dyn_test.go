package xelf

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"testing"
)

func TestBuildDynamicInfo(t *testing.T) {
	f, err := getELFFile("/bin/ls")
	if err != nil {
		log.Fatal(err)
	}
	dynInfo, err := BuildDynamicInfo(f)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(dynInfo)
}
