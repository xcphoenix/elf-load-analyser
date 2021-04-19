// env env about, eg kernel version, env type
package env

import (
	"bufio"
	"compress/gzip"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
)

const (
	kernelReleaseFile  = "/proc/sys/kernel/osrelease"
	kernelConfigGzFile = "/proc/config.gz"
)

// cache version result
var once sync.Once
var kernelVersion string

// GetSysOS get os type and arch
func GetSysOS() string {
	return runtime.GOOS
}

// GetKernelVersion get linux version
func GetKernelVersion() string {
	once.Do(extraKernelVersion)
	return kernelVersion
}

// ValidateKernelConfigs get kernel configs from kernelConfigGzFile
func ValidateKernelConfigs(target ...string) bool {
	file, err := os.Open(kernelConfigGzFile)
	if err != nil {
		log.Errorf("Open config file %q failed, %v", kernelConfigGzFile, err)
	}
	defer func() { _ = file.Close() }()

	reader, err := gzip.NewReader(file)
	if err != nil {
		log.Errorf("Reset file %q err, %v", kernelConfigGzFile, err)
	}
	//goland:noinspection GoUnhandledErrorResult
	defer reader.Close()

	var configLen = len(target)
	var config = make(map[string]struct{})
	for i := range target {
		config[target[i]] = struct{}{}
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		item := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(item, "CONFIG") {
			kv := strings.FieldsFunc(item, equalCharFunc)
			if len(kv) < 2 {
				continue
			}
			if _, ok := config[kv[0]]; ok {
				if strings.ToLower(kv[1]) != "y" {
					return false
				}
				configLen--
			}
		}
	}

	return configLen == 0
}

func extraKernelVersion() {
	// check env type
	helper.EqualWithTip("linux", GetSysOS(), "Unsupported env, the toolkit just for linux")

	file, err := os.Open(kernelReleaseFile)
	if err != nil {
		log.Errorf("Open release file %q failed, %v", kernelReleaseFile, err)
	}
	defer file.Close()
	release, err := ioutil.ReadAll(file)
	if err != nil {
		log.Errorf("Read %q failed, %v", kernelReleaseFile, err)
	}
	kernelVersion = strings.TrimSpace(string(release))
}

func equalCharFunc(r rune) bool {
	return r == '='
}
